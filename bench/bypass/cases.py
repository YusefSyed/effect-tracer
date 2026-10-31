#!/usr/bin/env python3
"""The seeded-bypass corpus: 20 ways a process can produce an undeclared
effect, each a small function. The harness (bench/corpus.py) runs one case
per tracer invocation and looks for the expected event in the ledger.

Environment: ET_OUT (undeclared directory), ET_ROOT (declared work root),
ET_TCP_PORT, ET_UDP_PORT (undeclared listeners the harness runs outside the
trace), ET_DNS_PORT (the DNS stub), ET_UNIX (an undeclared unix socket path).

Run one case:  python3 bench/bypass/cases.py <id>
"""

import ctypes
import mmap
import os
import socket
import struct
import subprocess
import sys
import threading

OUT = os.environ.get("ET_OUT", "/tmp/et-bypass-out")
ROOT = os.environ.get("ET_ROOT", "/tmp/et-bypass-root")


def env_port(name):
    return int(os.environ[name])


def c01_subprocess_redirect():
    subprocess.run(["/bin/sh", "-c", f"echo leak > {OUT}/c01"], check=True)


def c02_os_system():
    os.system(f"cat /etc/hostname > {OUT}/c02")


def c03_rename_over():
    tmp = os.path.join(ROOT, ".staging03")
    with open(tmp, "w") as f:
        f.write("leak\n")
    os.rename(tmp, os.path.join(OUT, "c03"))


def c04_tmpfile_linkat():
    fd = os.open(OUT, os.O_TMPFILE | os.O_WRONLY, 0o644)
    os.write(fd, b"leak\n")
    os.link(f"/proc/self/fd/{fd}", os.path.join(OUT, "c04"))
    os.close(fd)


def c05_shared_mmap():
    fd = os.open(os.path.join(OUT, "c05"), os.O_RDWR)
    m = mmap.mmap(fd, 4096, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
    m[:4] = b"leak"
    m.flush()
    m.close()
    os.close(fd)


def c06_sendfile():
    src = os.open("/etc/hostname", os.O_RDONLY)
    dst = os.open(os.path.join(OUT, "c06"), os.O_WRONLY | os.O_CREAT, 0o644)
    os.sendfile(dst, src, 0, 4096)
    os.close(src)
    os.close(dst)


def c07_dev_shm():
    with open("/dev/shm/et-c07", "w") as f:
        f.write("leak\n")
    os.unlink("/dev/shm/et-c07")


def c08_raw_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"leak", ("127.0.0.1", env_port("ET_UDP_PORT")))
    s.close()


def c09_unix_socket():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(os.environ["ET_UNIX"])
    s.sendall(b"leak")
    s.close()


def c10_io_uring():
    libc = ctypes.CDLL(None, use_errno=True)
    params = ctypes.create_string_buffer(120)
    r = libc.syscall(425, 4, params)
    err = ctypes.get_errno()
    print(f"io_uring_setup={r} errno={err}")
    if r >= 0:
        os.close(r)


def c11_copy_file_range():
    src = os.open("/etc/hostname", os.O_RDONLY)
    dst = os.open(os.path.join(OUT, "c11"), os.O_WRONLY | os.O_CREAT, 0o644)
    os.copy_file_range(src, dst, 4096)
    os.close(src)
    os.close(dst)


def c12_symlink_escape():
    link = os.path.join(ROOT, "link12")
    os.symlink(os.path.join(OUT, "c12"), link)
    with open(link, "w") as f:
        f.write("leak\n")


def c13_hardlink_in():
    os.link(os.path.join(OUT, "c13-src"), os.path.join(ROOT, "c13"))


def c14_truncate_path():
    os.truncate(os.path.join(OUT, "c14"), 0)


def c15_chmod():
    os.chmod(os.path.join(OUT, "c15"), 0o600)


def c16_unlink():
    os.unlink(os.path.join(OUT, "c16"))


def c17_mkdir():
    os.mkdir(os.path.join(OUT, "c17"))


def c18_dns_query():
    name = "exfil.undeclared.test"
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(q, ("127.0.0.1", env_port("ET_DNS_PORT")))
    s.recvfrom(512)
    s.close()


def c19_tcp_connect():
    s = socket.create_connection(("127.0.0.1", env_port("ET_TCP_PORT")), timeout=5)
    s.sendall(b"leak")
    s.close()


def c20_exec_undeclared():
    subprocess.run(["/usr/bin/env", "true"], check=True)


# Additional cases, reported separately from the 20 above.

def x21_thread_write():
    def work():
        with open(os.path.join(OUT, "x21"), "w") as f:
            f.write("leak\n")
    t = threading.Thread(target=work)
    t.start()
    t.join()


def x22_fork_write():
    pid = os.fork()
    if pid == 0:
        with open(os.path.join(OUT, "x22"), "w") as f:
            f.write("leak\n")
        os._exit(0)
    os.waitpid(pid, 0)


def x23_memfd():
    fd = os.memfd_create("leak23")
    os.write(fd, b"leak")
    os.close(fd)


def x24_splice():
    r, w = os.pipe()
    os.write(w, b"leak\n")
    os.close(w)
    dst = os.open(os.path.join(OUT, "x24"), os.O_WRONLY | os.O_CREAT, 0o644)
    os.splice(r, dst, 4096)
    os.close(r)
    os.close(dst)


def _nondumpable():
    # ssh-agent and gpg-agent do this; an unprivileged tracer then cannot
    # read /proc/<pid>/fd or the process's memory
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    PR_SET_DUMPABLE = 4
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE, 0)")


def x25_nondumpable_ftruncate():
    fd = os.open(os.path.join(OUT, "x25"), os.O_WRONLY | os.O_CREAT, 0o644)
    _nondumpable()
    os.ftruncate(fd, 0)
    os.close(fd)


def x26_nondumpable_connect():
    _nondumpable()
    s = socket.create_connection(("127.0.0.1", env_port("ET_TCP_PORT")), timeout=5)
    s.close()


CASES = {f.__name__[:3]: f for f in [
    c01_subprocess_redirect, c02_os_system, c03_rename_over, c04_tmpfile_linkat, c05_shared_mmap,
    c06_sendfile, c07_dev_shm, c08_raw_udp, c09_unix_socket, c10_io_uring, c11_copy_file_range,
    c12_symlink_escape, c13_hardlink_in, c14_truncate_path, c15_chmod, c16_unlink, c17_mkdir,
    c18_dns_query, c19_tcp_connect, c20_exec_undeclared,
    x21_thread_write, x22_fork_write, x23_memfd, x24_splice,
    x25_nondumpable_ftruncate, x26_nondumpable_connect,
]}


if __name__ == "__main__":
    CASES[sys.argv[1]]()
    print(f"case {sys.argv[1]} done")
