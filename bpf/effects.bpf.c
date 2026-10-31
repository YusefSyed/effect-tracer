// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
//
// eBPF backend for effect-tracer: LSM hooks see the kernel's own objects
// (the file actually opened, the dentry actually unlinked, the socket
// actually connected), raw_tp/sys_exit supplies the outcome, and a lineage
// map that follows fork limits everything to the traced tree.
//
// Event flow: an LSM hook fills a per-CPU scratch event and parks it in
// `pending` under the thread id; the next sys_exit of that thread copies
// the return value in and pushes the event to the ring buffer. Exec, fork,
// exit and gaps have no syscall outcome to wait for and go out directly.
//
// Dual MIT/GPL so the kernel accepts the GPL-only helpers (bpf_d_path,
// bpf_probe_read_*) the LSM programs need; the rest of the repository is
// Apache-2.0.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define PATH_LEN 256
#define NAME_LEN 256
#define DATA_LEN 512

#define FMODE_WRITE 0x2
#define O_CREAT 00000100
#define O_TRUNC 00001000
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10
#define SOCK_DGRAM 2

enum kind {
	K_OPEN = 1,
	K_UNLINK,
	K_RMDIR,
	K_MKDIR,
	K_RENAME,
	K_LINK,
	K_SYMLINK,
	K_TRUNCATE,
	K_CHMOD,
	K_CONNECT,
	K_BIND,
	K_SEND,
	K_EXEC,
	K_FORK,
	K_EXIT,
	K_GAP,
	K_WRITE_VIA,
	K_MEMFD,
	K_MAP_WRITE,
};

// Kept in step with `Event` in src/sys/ebpf.rs (repr(C)).
struct event {
	__u64 ts;
	__u32 kind;
	__u32 tgid;
	__u32 tid;
	__u32 ppid;
	__u64 start_ns;
	__s64 ret;
	__u32 flags;
	__u32 mode;
	__u32 aux;
	__u16 family;
	__u16 port;
	__u32 sotype;
	__u32 path_len;
	__u32 name_len;
	__u32 path2_len;
	__u32 name2_len;
	__u32 data_len;
	__u8 addr[16];
	char comm[16];
	char path[PATH_LEN];
	char name[NAME_LEN];
	char path2[PATH_LEN];
	char name2[NAME_LEN];
	__u8 data[DATA_LEN];
};

const volatile __u32 trace_reads = 0;
// The tracer renames itself to this token for the one fork that starts the
// tree, so the fork tracepoint can adopt the root without knowing the
// tracer's pid as the kernel sees it (it may sit in a pid namespace).
const volatile char root_token[16] = {};
// Syscall numbers of this architecture, filled in by the loader.
const volatile __s64 nr_sendfile = -1;
const volatile __s64 nr_copy_file_range = -1;
const volatile __s64 nr_splice = -1;
const volatile __s64 nr_memfd_create = -1;
const volatile __s64 nr_io_uring_setup = -1;
const volatile __s64 nr_io_uring_enter = -1;
const volatile __s64 nr_io_uring_register = -1;

// [0] pid-namespace level of the tracer (and the tree), [1] root adopted
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u32);
} cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32); // tgid
	__type(value, __u8);
} traced SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32); // tid
	__type(value, struct event);
} pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32); // tid, between bprm_committed_creds and sched_process_exec
	__type(value, struct event);
} execs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u16); // DNS ports, host order
	__type(value, __u8);
} dns_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64); // struct socket * connected to a DNS port
	__type(value, __u8);
} dns_socks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct event);
} heap SEC(".maps");

// [0] ring buffer drops, [1] live processes in the tree, [2] pending overwrites
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __s64);
} counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 << 20);
} rb SEC(".maps");

// Scratch for walk_path: components are written backwards from offset 511,
// so the 1 KiB value keeps every write in bounds for the verifier.
struct pbuf {
	char b[1024];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pbuf);
} pbuf SEC(".maps");

// A read size the verifier can prove is in [0, DATA_LEN]: the empty asm
// stops clang from folding the checks into a signed compare.
static __always_inline __u32 data_size(__s64 v)
{
	__u32 n = 0;
	if (v > 0)
		n = v > DATA_LEN ? DATA_LEN : (__u32)v;
	asm volatile("" : "+r"(n));
	n &= (DATA_LEN * 2 - 1);
	if (n > DATA_LEN)
		n = DATA_LEN;
	return n;
}

static __always_inline void count(__u32 idx, __s64 delta)
{
	__s64 *v = bpf_map_lookup_elem(&counters, &idx);
	if (v)
		__sync_fetch_and_add(v, delta);
}

// A task's pid as seen from pid-namespace `level` (the tracer's), the way
// task_pid_nr_ns does it: pid->numbers[level].nr.
static __always_inline __u32 ns_nr(struct pid *p, __u32 level)
{
	if (!p)
		return 0;
	__u32 plevel = BPF_CORE_READ(p, level);
	if (level > plevel)
		return 0;
	void *at = (void *)p + bpf_core_field_offset(struct pid, numbers) +
		   (level & 31) * bpf_core_type_size(struct upid) + bpf_core_field_offset(struct upid, nr);
	int nr = 0;
	bpf_probe_read_kernel(&nr, sizeof(nr), at);
	return nr;
}

static __always_inline __u32 ns_level(void)
{
	__u32 zero = 0;
	__u32 *l = bpf_map_lookup_elem(&cfg, &zero);
	return l ? *l : 0;
}

static __always_inline __u32 ns_tid(struct task_struct *t)
{
	return ns_nr(BPF_CORE_READ(t, thread_pid), ns_level());
}

static __always_inline __u32 ns_tgid(struct task_struct *t)
{
	return ns_nr(BPF_CORE_READ(t, group_leader, thread_pid), ns_level());
}

static __always_inline bool traced_now(void)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	return bpf_map_lookup_elem(&traced, &tgid) != NULL;
}

static __always_inline struct event *start(__u32 kind)
{
	__u32 zero = 0;
	struct event *e = bpf_map_lookup_elem(&heap, &zero);
	if (!e)
		return NULL;
	struct task_struct *t = bpf_get_current_task_btf();
	e->ts = bpf_ktime_get_ns();
	e->kind = kind;
	e->tgid = ns_tgid(t);
	e->tid = ns_tid(t);
	e->ppid = ns_tgid(BPF_CORE_READ(t, real_parent));
	e->start_ns = BPF_CORE_READ(t, group_leader, start_boottime);
	e->ret = 0;
	e->flags = 0;
	e->mode = 0;
	e->aux = 0;
	e->family = 0;
	e->port = 0;
	e->sotype = 0;
	e->path_len = 0;
	e->name_len = 0;
	e->path2_len = 0;
	e->name2_len = 0;
	e->data_len = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

// Park the event until this thread's sys_exit.
static __always_inline void pend(struct event *e)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	if (bpf_map_lookup_elem(&pending, &tid))
		count(2, 1);
	bpf_map_update_elem(&pending, &tid, e, BPF_ANY);
}

static __always_inline void emit(struct event *e)
{
	if (bpf_ringbuf_output(&rb, e, sizeof(*e), 0))
		count(0, 1);
}

static __always_inline void set_dir_and_name(struct event *e, const struct path *dir, struct dentry *d,
					     bool second)
{
	const unsigned char *n = BPF_CORE_READ(d, d_name.name);
	if (!second) {
		long l = bpf_d_path((struct path *)dir, e->path, PATH_LEN);
		e->path_len = l > 0 ? l : 0;
		l = bpf_probe_read_kernel_str(e->name, NAME_LEN, n);
		e->name_len = l > 0 ? l : 0;
	} else {
		long l = bpf_d_path((struct path *)dir, e->path2, PATH_LEN);
		e->path2_len = l > 0 ? l : 0;
		l = bpf_probe_read_kernel_str(e->name2, NAME_LEN, n);
		e->name2_len = l > 0 ? l : 0;
	}
}

// The absolute path of a dentry on a mount, for hooks where bpf_d_path is
// not allowed (non-sleepable ones). Walks d_parent and crosses mount points
// the way d_path does, at most 32 levels; returns the length written to
// `out` including the NUL, or 0. A path longer than PATH_LEN is cut.
static __always_inline __u32 walk_path(struct dentry *d, struct vfsmount *vm, char *out)
{
	__u32 zero = 0;
	struct pbuf *pb = bpf_map_lookup_elem(&pbuf, &zero);
	if (!pb)
		return 0;
	struct mount *mnt = (void *)vm - bpf_core_field_offset(struct mount, mnt);
	__u32 off = 511;
	pb->b[511] = 0;
	for (int i = 0; i < 32; i++) {
		struct dentry *mroot = BPF_CORE_READ(mnt, mnt.mnt_root);
		if (d == mroot) {
			struct mount *parent = BPF_CORE_READ(mnt, mnt_parent);
			if (parent == mnt)
				break;
			d = BPF_CORE_READ(mnt, mnt_mountpoint);
			mnt = parent;
			continue;
		}
		struct dentry *dp = BPF_CORE_READ(d, d_parent);
		if (dp == d)
			break;
		__u32 len = BPF_CORE_READ(d, d_name.len);
		const unsigned char *name = BPF_CORE_READ(d, d_name.name);
		if (len > 255 || len + 1 > off)
			break;
		off -= len;
		off &= 511;
		bpf_probe_read_kernel(&pb->b[off], len & 255, name);
		off -= 1;
		off &= 511;
		pb->b[off] = '/';
		d = dp;
	}
	if (off == 511) {
		off = 510;
		pb->b[510] = '/';
	}
	__u32 n = 512 - off;
	if (n > PATH_LEN)
		n = PATH_LEN;
	off &= 511;
	if (bpf_probe_read_kernel(out, n & (PATH_LEN * 2 - 1), &pb->b[off]))
		return 0;
	return n;
}

// ----- files -----

SEC("lsm.s/file_open")
int BPF_PROG(et_file_open, struct file *file)
{
	if (!traced_now())
		return 0;
	unsigned int fmode = BPF_CORE_READ(file, f_mode);
	unsigned int fl = BPF_CORE_READ(file, f_flags);
	bool writes = (fmode & FMODE_WRITE) || (fl & (O_CREAT | O_TRUNC));
	if (!writes && !trace_reads)
		return 0;
	// overlayfs opens the backing file inside the same syscall; keep the
	// path the caller asked for, not the upper-layer one
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	if (bpf_map_lookup_elem(&pending, &tid))
		return 0;
	struct event *e = start(K_OPEN);
	if (!e)
		return 0;
	e->flags = fl;
	e->mode = fmode;
	long l = bpf_d_path(&file->f_path, e->path, PATH_LEN);
	e->path_len = l > 0 ? l : 0;
	pend(e);
	return 0;
}

static __always_inline int dir_entry(__u32 kind, const struct path *dir, struct dentry *d, __u32 mode)
{
	if (!traced_now())
		return 0;
	struct event *e = start(kind);
	if (!e)
		return 0;
	e->mode = mode;
	set_dir_and_name(e, dir, d, false);
	pend(e);
	return 0;
}

SEC("lsm.s/path_unlink")
int BPF_PROG(et_unlink, const struct path *dir, struct dentry *dentry)
{
	return dir_entry(K_UNLINK, dir, dentry, 0);
}

SEC("lsm.s/path_rmdir")
int BPF_PROG(et_rmdir, const struct path *dir, struct dentry *dentry)
{
	return dir_entry(K_RMDIR, dir, dentry, 0);
}

SEC("lsm.s/path_mkdir")
int BPF_PROG(et_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode)
{
	return dir_entry(K_MKDIR, dir, dentry, mode);
}

SEC("lsm.s/path_symlink")
int BPF_PROG(et_symlink, const struct path *dir, struct dentry *dentry, const char *old_name)
{
	if (!traced_now())
		return 0;
	struct event *e = start(K_SYMLINK);
	if (!e)
		return 0;
	set_dir_and_name(e, dir, dentry, false);
	long l = bpf_probe_read_kernel_str(e->path2, PATH_LEN, old_name);
	e->path2_len = l > 0 ? l : 0;
	pend(e);
	return 0;
}

SEC("lsm.s/path_link")
int BPF_PROG(et_link, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry)
{
	if (!traced_now())
		return 0;
	struct event *e = start(K_LINK);
	if (!e)
		return 0;
	set_dir_and_name(e, new_dir, new_dentry, false);
	// a hard link cannot cross mounts, so the source is on new_dir's mount
	e->path2_len = walk_path(old_dentry, BPF_CORE_READ(new_dir, mnt), e->path2);
	pend(e);
	return 0;
}

SEC("lsm.s/path_rename")
int BPF_PROG(et_rename, const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry, unsigned int flags)
{
	if (!traced_now())
		return 0;
	struct event *e = start(K_RENAME);
	if (!e)
		return 0;
	e->flags = flags;
	set_dir_and_name(e, old_dir, old_dentry, false);
	set_dir_and_name(e, new_dir, new_dentry, true);
	pend(e);
	return 0;
}

// truncate(2). Also reached inside an O_TRUNC open and inside ftruncate
// after file_truncate; the event already parked for the syscall wins.
SEC("lsm.s/path_truncate")
int BPF_PROG(et_truncate, const struct path *path)
{
	if (!traced_now())
		return 0;
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	if (bpf_map_lookup_elem(&pending, &tid))
		return 0;
	struct event *e = start(K_TRUNCATE);
	if (!e)
		return 0;
	long l = bpf_d_path((struct path *)path, e->path, PATH_LEN);
	e->path_len = l > 0 ? l : 0;
	pend(e);
	return 0;
}

// ftruncate, and the O_TRUNC step of an open (which must not displace the
// open itself, already parked for this thread).
SEC("lsm/file_truncate")
int BPF_PROG(et_file_truncate, struct file *file)
{
	if (!traced_now())
		return 0;
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	if (bpf_map_lookup_elem(&pending, &tid))
		return 0;
	struct event *e = start(K_TRUNCATE);
	if (!e)
		return 0;
	e->aux = 1; // via ftruncate
	e->path_len = walk_path(BPF_CORE_READ(file, f_path.dentry), BPF_CORE_READ(file, f_path.mnt), e->path);
	pend(e);
	return 0;
}

SEC("lsm.s/path_chmod")
int BPF_PROG(et_chmod, const struct path *path, umode_t mode)
{
	if (!traced_now())
		return 0;
	struct event *e = start(K_CHMOD);
	if (!e)
		return 0;
	e->mode = mode;
	long l = bpf_d_path((struct path *)path, e->path, PATH_LEN);
	e->path_len = l > 0 ? l : 0;
	pend(e);
	return 0;
}

// ----- sockets -----

static __always_inline void read_sockaddr(struct event *e, struct sockaddr *a, int len)
{
	__u16 fam = BPF_CORE_READ(a, sa_family);
	e->family = fam;
	if (fam == AF_INET) {
		struct sockaddr_in *in = (void *)a;
		e->port = bpf_ntohs(BPF_CORE_READ(in, sin_port));
		bpf_probe_read_kernel(e->addr, 4, &in->sin_addr);
	} else if (fam == AF_INET6) {
		struct sockaddr_in6 *in6 = (void *)a;
		e->port = bpf_ntohs(BPF_CORE_READ(in6, sin6_port));
		bpf_probe_read_kernel(e->addr, 16, &in6->sin6_addr);
	} else if (fam == AF_UNIX) {
		struct sockaddr_un *un = (void *)a;
		// abstract names start with a NUL; keep the raw bytes and the length
		__u32 n = 0;
		if (len > 2)
			n = (__u32)len - 2;
		if (n > sizeof(un->sun_path))
			n = sizeof(un->sun_path);
		asm volatile("" : "+r"(n));
		n &= 0x7f;
		bpf_probe_read_kernel(e->path, n, un->sun_path);
		e->path_len = n;
	}
}

static __always_inline bool is_dns_port(__u16 port)
{
	return bpf_map_lookup_elem(&dns_ports, &port) != NULL;
}

static __always_inline int sock_addr_hook(__u32 kind, struct socket *sock, struct sockaddr *address, int addrlen)
{
	if (!traced_now())
		return 0;
	struct event *e = start(kind);
	if (!e)
		return 0;
	e->sotype = BPF_CORE_READ(sock, type);
	read_sockaddr(e, address, addrlen);
	if (kind == K_CONNECT && e->sotype == SOCK_DGRAM && is_dns_port(e->port)) {
		__u64 key = (__u64)sock;
		__u8 one = 1;
		bpf_map_update_elem(&dns_socks, &key, &one, BPF_ANY);
	}
	pend(e);
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(et_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	return sock_addr_hook(K_CONNECT, sock, address, addrlen);
}

SEC("lsm/socket_bind")
int BPF_PROG(et_bind, struct socket *sock, struct sockaddr *address, int addrlen)
{
	return sock_addr_hook(K_BIND, sock, address, addrlen);
}

// Every socket send passes here (sendto, sendmsg, sendmmsg, and plain write
// on a socket). Only sends with an explicit destination, and any send on a
// socket connected to a DNS port, become events.
SEC("lsm/socket_sendmsg")
int BPF_PROG(et_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
	if (!traced_now())
		return 0;
	int namelen = BPF_CORE_READ(msg, msg_namelen);
	__u64 key = (__u64)sock;
	bool dns_sock = bpf_map_lookup_elem(&dns_socks, &key) != NULL;
	if (namelen <= 0 && !dns_sock)
		return 0;
	struct event *e = start(K_SEND);
	if (!e)
		return 0;
	e->sotype = BPF_CORE_READ(sock, type);
	e->aux = size;
	if (namelen > 0) {
		struct sockaddr *a = BPF_CORE_READ(msg, msg_name);
		read_sockaddr(e, a, namelen);
	} else {
		e->flags = 1; // connected resolver socket, no destination in the call
	}
	if (e->sotype == SOCK_DGRAM && (dns_sock || is_dns_port(e->port))) {
		__u8 t = BPF_CORE_READ(msg, msg_iter.iter_type);
		const void *base = NULL;
		if (t == ITER_UBUF) {
			base = BPF_CORE_READ(msg, msg_iter.ubuf);
		} else if (t == ITER_IOVEC) {
			const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
			base = BPF_CORE_READ(iov, iov_base);
		}
		__u32 n = data_size(size);
		if (base && bpf_probe_read_user(e->data, n, base) == 0)
			e->data_len = n;
	}
	pend(e);
	return 0;
}

// ----- processes -----

// The resolved executable, before the new image runs; finished and sent at
// sched_process_exec, when argv is in place in the new mm.
SEC("lsm.s/bprm_committed_creds")
int BPF_PROG(et_bprm, struct linux_binprm *bprm)
{
	if (!traced_now())
		return 0;
	struct event *e = start(K_EXEC);
	if (!e)
		return 0;
	long l = bpf_d_path(&bprm->file->f_path, e->path, PATH_LEN);
	e->path_len = l > 0 ? l : 0;
	const char *fn = BPF_CORE_READ(bprm, filename);
	l = bpf_probe_read_kernel_str(e->name, NAME_LEN, fn);
	e->name_len = l > 0 ? l : 0;
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&execs, &tid, e, BPF_ANY);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(et_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	if (!traced_now())
		return 0;
	// bprm_committed_creds ran on the thread that called execve; after a
	// non-leader exec that thread has taken the leader's id.
	__u32 key = old_pid;
	struct event *e = bpf_map_lookup_elem(&execs, &key);
	if (!e)
		return 0;
	struct mm_struct *mm = BPF_CORE_READ(p, mm);
	unsigned long as = BPF_CORE_READ(mm, arg_start);
	unsigned long ae = BPF_CORE_READ(mm, arg_end);
	__s64 full = ae > as ? ae - as : 0;
	e->aux = full; // full argv length; data holds at most DATA_LEN of it
	__u32 n = data_size(full);
	if (bpf_probe_read_user(e->data, n, (void *)as) == 0)
		e->data_len = n;
	e->tid = ns_tid(p);
	e->tgid = ns_tgid(p);
	e->flags = old_pid;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->ts = bpf_ktime_get_ns();
	emit(e);
	bpf_map_delete_elem(&execs, &key);
	return 0;
}

static __always_inline bool is_root_fork(struct task_struct *parent)
{
	__u32 one_idx = 1;
	__u32 *adopted = bpf_map_lookup_elem(&cfg, &one_idx);
	if (!adopted || *adopted || root_token[0] == 0)
		return false;
	char comm[16];
	bpf_probe_read_kernel(comm, sizeof(comm), &parent->comm);
	for (int i = 0; i < 16; i++) {
		if (comm[i] != root_token[i])
			return false;
		if (comm[i] == 0)
			break;
	}
	return true;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(et_fork, struct task_struct *parent, struct task_struct *child)
{
	__u32 ptgid = BPF_CORE_READ(parent, tgid);
	__u32 ctgid = BPF_CORE_READ(child, tgid);
	__u8 one = 1;
	if (!bpf_map_lookup_elem(&traced, &ptgid)) {
		if (!is_root_fork(parent))
			return 0;
		// the tree starts here: remember the namespace level, adopt the child
		__u32 zero = 0, one_idx = 1, yes = 1;
		__u32 level = BPF_CORE_READ(child, thread_pid, level);
		bpf_map_update_elem(&cfg, &zero, &level, BPF_ANY);
		bpf_map_update_elem(&cfg, &one_idx, &yes, BPF_ANY);
		bpf_map_update_elem(&traced, &ctgid, &one, BPF_ANY);
		count(1, 1);
		return 0;
	}
	if (ctgid != ptgid) {
		bpf_map_update_elem(&traced, &ctgid, &one, BPF_ANY);
		count(1, 1);
	}
	struct event *e = start(K_FORK);
	if (!e)
		return 0;
	e->flags = ns_tgid(child);
	e->mode = ns_tid(child);
	e->aux = ctgid == ptgid; // a thread
	e->ret = BPF_CORE_READ(child, start_boottime); // names the new process
	emit(e);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(et_exit, struct task_struct *p)
{
	__u32 tgid = BPF_CORE_READ(p, tgid);
	__u32 pid = BPF_CORE_READ(p, pid);
	__u32 tid = pid;
	bpf_map_delete_elem(&pending, &tid);
	if (pid != tgid || !bpf_map_lookup_elem(&traced, &tgid))
		return 0;
	struct event *e = start(K_EXIT);
	if (e) {
		e->tgid = ns_tgid(p);
		e->tid = ns_tid(p);
		e->flags = BPF_CORE_READ(p, exit_code);
		emit(e);
	}
	bpf_map_delete_elem(&traced, &tgid);
	count(1, -1);
	return 0;
}

// ----- syscalls with no LSM hook of their own -----

// The struct file behind descriptor `fd` of the current task.
static __always_inline struct file *fd_file(long fd)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct fdtable *fdt = BPF_CORE_READ(t, files, fdt);
	unsigned int max = BPF_CORE_READ(fdt, max_fds);
	if (fd < 0 || fd >= max)
		return NULL;
	struct file **arr = BPF_CORE_READ(fdt, fd);
	struct file *f = NULL;
	bpf_probe_read_kernel(&f, sizeof(f), &arr[fd & 0xffff]);
	return f;
}

// sendfile, copy_file_range and splice move data into a file without a
// write(2) or an open; memfd_create makes an anonymous file.
SEC("raw_tp/sys_enter")
int BPF_PROG(et_sys_enter, struct pt_regs *regs, long id)
{
	if (id != nr_sendfile && id != nr_copy_file_range && id != nr_splice && id != nr_memfd_create)
		return 0;
	if (!traced_now())
		return 0;
	if (id == nr_memfd_create) {
		struct event *e = start(K_MEMFD);
		if (!e)
			return 0;
		const char *name = (const char *)PT_REGS_PARM1_CORE_SYSCALL(regs);
		long l = bpf_probe_read_user_str(e->name, NAME_LEN, name);
		e->name_len = l > 0 ? l : 0;
		pend(e);
		return 0;
	}
	long fd = id == nr_sendfile ? PT_REGS_PARM1_CORE_SYSCALL(regs) : PT_REGS_PARM3_CORE_SYSCALL(regs);
	struct file *f = fd_file(fd);
	if (!f)
		return 0;
	umode_t mode = BPF_CORE_READ(f, f_inode, i_mode);
	if ((mode & 0170000) != 0100000) // regular files only; sockets are socket.send
		return 0;
	struct event *e = start(K_WRITE_VIA);
	if (!e)
		return 0;
	e->aux = id == nr_sendfile ? 1 : id == nr_copy_file_range ? 2 : 3;
	e->path_len = walk_path(BPF_CORE_READ(f, f_path.dentry), BPF_CORE_READ(f, f_path.mnt), e->path);
	pend(e);
	return 0;
}

// A shared writable mapping: later stores into it are plain memory writes.
SEC("lsm/mmap_file")
int BPF_PROG(et_mmap, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
	if (!file || !(prot & 0x2) || !(flags & 0x1) || !traced_now())
		return 0;
	struct event *e = start(K_MAP_WRITE);
	if (!e)
		return 0;
	e->path_len = walk_path(BPF_CORE_READ(file, f_path.dentry), BPF_CORE_READ(file, f_path.mnt), e->path);
	pend(e);
	return 0;
}

// ----- outcome -----

static __always_inline long syscall_nr(struct pt_regs *regs)
{
#if defined(__TARGET_ARCH_arm64)
	return BPF_CORE_READ(regs, syscallno);
#else
	return BPF_CORE_READ(regs, orig_ax);
#endif
}

SEC("raw_tp/sys_exit")
int BPF_PROG(et_sys_exit, struct pt_regs *regs, long ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct event *e = bpf_map_lookup_elem(&pending, &tid);
	if (!e) {
		// The seccomp filter's EPERM for io_uring skips sys_enter (seccomp
		// runs first) but not sys_exit: record the attempt here.
		if (ret != -1)
			return 0;
		long nr = syscall_nr(regs);
		if (nr != nr_io_uring_setup && nr != nr_io_uring_enter && nr != nr_io_uring_register)
			return 0;
		if (!traced_now())
			return 0;
		struct event *g = start(K_GAP);
		if (!g)
			return 0;
		g->flags = nr == nr_io_uring_setup ? 4 : nr == nr_io_uring_enter ? 5 : 6;
		g->ret = ret;
		emit(g);
		return 0;
	}
	e->ret = ret;
	emit(e);
	bpf_map_delete_elem(&pending, &tid);
	return 0;
}

// ----- things that make the ledger's names unreliable or reach outside -----

static __always_inline int gap(__u32 what)
{
	if (!traced_now())
		return 0;
	struct event *e = start(K_GAP);
	if (!e)
		return 0;
	e->flags = what;
	emit(e);
	return 0;
}

SEC("lsm/sb_mount")
int BPF_PROG(et_mount, const char *dev_name, const struct path *path, const char *type, unsigned long flags,
	     void *data)
{
	return gap(1);
}

SEC("lsm/bpf")
int BPF_PROG(et_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
	return gap(2);
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(et_ptrace, struct task_struct *child, unsigned int mode)
{
	// PTRACE_MODE_ATTACH only: /proc readers (ps) check PTRACE_MODE_READ
	if (!(mode & 0x02))
		return 0;
	return gap(3);
}
