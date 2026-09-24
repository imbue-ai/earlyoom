#!/usr/bin/env python3
"""Check earlyoom's kill order under real memory pressure.

Runs as the entrypoint of a memory-limited container (see ci.yml's runsc job).
It starts earlyoom, then sleepers that each hold a fixed amount of memory at a
given oom_score_adj, then a hog at oom_score_adj -1000 that grows until the
last sleeper is gone. The sleepers are sized so that the largest RSS carries
the smallest oom_score_adj: ordering by RSS alone (what upstream earlyoom does
under gVisor, where every oom_score reads 0) kills them in the opposite order
from the kernel's badness.

Exit status 0 means the kill order matched --expect:

  badness  every sleeper was killed, in descending badness order
  not-badness  the first sleeper killed was not the one with the highest
           badness (the control run against upstream earlyoom)
"""

import argparse
import json
import os
import subprocess
import sys
import time

MIB = 1024 * 1024
HOOK_LOG = "/tmp/earlyoom-kills.log"
HOOK_PATH = "/tmp/earlyoom-hook.sh"

# (oom_score_adj, MiB held). Larger RSS, smaller adj.
SLEEPERS = ((1000, 10), (900, 30), (500, 60), (300, 80), (100, 100))

SLEEPER_CODE = """
import sys, time
adj, mib = int(sys.argv[1]), int(sys.argv[2])
with open("/proc/self/oom_score_adj", "w") as f:
    f.write(str(adj))
block = bytearray(mib * 1024 * 1024)
for i in range(0, len(block), 4096):
    block[i] = 1
print("ready", flush=True)
while True:
    time.sleep(3600)
"""


def set_own_adj(adj: int) -> None:
    with open("/proc/self/oom_score_adj", "w") as f:
        f.write(str(adj))


def meminfo_kib(field: str) -> int:
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith(field + ":"):
                return int(line.split()[1])
    raise RuntimeError(f"no {field} in /proc/meminfo")


def rss_kib(pid: int) -> int:
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


def badness_kib(adj: int, rss: int, total_kib: int) -> int:
    return rss + adj * total_kib // 1000


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--earlyoom", required=True)
    parser.add_argument("--expect", choices=("badness", "not-badness"), required=True)
    parser.add_argument("--timeout", type=float, default=240)
    args = parser.parse_args()

    # This process must outlive the sleepers.
    set_own_adj(-1000)

    with open(HOOK_PATH, "w") as f:
        f.write(
            "#!/bin/sh\n"
            f'echo "$EARLYOOM_PID ${{EARLYOOM_OOM_SCORE_ADJ:-}} ${{EARLYOOM_BADNESS_KIB:-}} ${{EARLYOOM_ORDERING:-}}" >> {HOOK_LOG}\n'
        )
    os.chmod(HOOK_PATH, 0o755)

    total_kib = meminfo_kib("MemTotal") + meminfo_kib("SwapTotal")
    print(f"MemTotal+SwapTotal: {total_kib // 1024} MiB", flush=True)

    earlyoom_log = open("/tmp/earlyoom.log", "w")
    earlyoom = subprocess.Popen(
        [args.earlyoom, "-m", "10,5", "-s", "10,5", "-r", "0", "-N", HOOK_PATH],
        stdout=earlyoom_log,
        stderr=subprocess.STDOUT,
    )
    time.sleep(1)

    sleepers = {}
    for adj, mib in SLEEPERS:
        proc = subprocess.Popen(
            [sys.executable, "-c", SLEEPER_CODE, str(adj), str(mib)],
            stdout=subprocess.PIPE,
            text=True,
        )
        assert proc.stdout is not None
        if proc.stdout.readline().strip() != "ready":
            raise RuntimeError(f"sleeper adj={adj} did not start")
        sleepers[proc.pid] = (proc, adj)

    predicted = sorted(
        ((badness_kib(adj, rss_kib(pid), total_kib), pid, adj) for pid, (_, adj) in sleepers.items()),
        reverse=True,
    )
    print("predicted order (badness KiB, pid, adj):", predicted, flush=True)

    # The hog grows in small steps and pauses after each kill, so earlyoom
    # picks one victim at a time.
    hog_code = (
        "import time\n"
        "open('/proc/self/oom_score_adj','w').write('-1000')\n"
        "blocks = []\n"
        "while True:\n"
        "    b = bytearray(4 * 1024 * 1024)\n"
        "    for i in range(0, len(b), 4096): b[i] = 1\n"
        "    blocks.append(b)\n"
        "    time.sleep(0.05)\n"
    )
    hog = subprocess.Popen([sys.executable, "-c", hog_code])

    # The control only needs the first kill.
    wanted = len(sleepers) if args.expect == "badness" else 1
    killed = []
    deadline = time.monotonic() + args.timeout
    try:
        while len(killed) < wanted and time.monotonic() < deadline and hog.poll() is None:
            for pid, (proc, adj) in sleepers.items():
                if proc.poll() is not None and pid not in {k for k, _ in killed}:
                    killed.append((pid, adj))
                    print(f"killed pid {pid} adj {adj}", flush=True)
            time.sleep(0.1)
    finally:
        hog.kill()
        for proc, _ in sleepers.values():
            proc.kill()
        earlyoom.kill()
        earlyoom_log.close()

    with open("/tmp/earlyoom.log") as f:
        print("--- earlyoom log ---\n" + f.read(), flush=True)
    hook_lines = open(HOOK_LOG).read().splitlines() if os.path.exists(HOOK_LOG) else []
    print("--- hook log ---\n" + "\n".join(hook_lines), flush=True)

    predicted_adjs = [adj for _, _, adj in predicted]
    killed_adjs = [adj for _, adj in killed]
    verdict = {"expect": args.expect, "predicted_adjs": predicted_adjs, "killed_adjs": killed_adjs}
    print(json.dumps(verdict), flush=True)

    if args.expect == "badness":
        if killed_adjs != predicted_adjs:
            print("FAIL: kill order does not follow badness", flush=True)
            return 1
        orderings = {line.split()[-1] for line in hook_lines if line.split()}
        if orderings != {"kernel_badness"}:
            print(f"FAIL: hook saw orderings {orderings}", flush=True)
            return 1
        return 0
    if not killed_adjs:
        print("FAIL: nothing was killed", flush=True)
        return 1
    if killed_adjs[0] == predicted_adjs[0]:
        print("FAIL: the control killed the highest-badness sleeper first", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
