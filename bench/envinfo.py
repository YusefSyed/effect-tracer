#!/usr/bin/env python3
"""Print the environment block every bench JSON carries."""
import json
import os
import platform
import subprocess
import sys
import time


def sh(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception as e:  # noqa: BLE001
        return f"unavailable: {e}"


def info(tracer="target/release/effect-tracer"):
    cpus = os.cpu_count()
    mem_kb = None
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_kb = int(line.split()[1])
    except OSError:
        pass
    container = os.path.exists("/.dockerenv")
    return {
        "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "os": sh(["sh", "-c", ". /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\""]),
        "cpus": cpus,
        "memTotalMiB": mem_kb // 1024 if mem_kb else None,
        "inDockerContainer": container,
        "python": platform.python_version(),
        "tracer": sh([tracer, "--version"]),
        "tracerBuild": "release" if "release" in tracer else "debug",
        "hyperfine": sh(["hyperfine", "--version"]),
        "hostNote": os.environ.get("BENCH_HOST_NOTE", ""),
    }


if __name__ == "__main__":
    print(json.dumps(info(*sys.argv[1:]), indent=2))
