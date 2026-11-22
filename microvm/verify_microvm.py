#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Standalone MicroVM isolation evidence for GitHub Actions (no project imports)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cg_tz_microvm_runtime import (MicroVmAssets, QemuMicroVm,
                                  QemuMicroVmFactory, MicroVmQuotaError)


def main() -> int:
    a = MicroVmAssets.discover()
    # GitHub runners expose /dev/kvm but the unprivileged job user cannot use it;
    # the workflow pins TCG explicitly so the evidence path stays runnable.
    a.accel = os.environ.get("CGT_MICROVM_ACCEL", a.accel)
    evidence = {"assets": a.manifest(), "tests": []}
    if not a.available:
        print(json.dumps({"ok": False, "reason": "assets unavailable",
                          "missing": a.missing()}, ensure_ascii=False))
        return 2

    def record(name, ok, detail):
        evidence["tests"].append({"name": name, "ok": bool(ok), "detail": detail})
        print(("PASS " if ok else "FAIL ") + name + " :: " + str(detail))

    r = QemuMicroVm(a, timeout_s=20).run(
        "uname -r; nproc; head -1 /proc/meminfo; ls /sys/class/net")
    lines = r.stdout.splitlines()
    record("real_guest_kernel", r.ok and lines and lines[0].startswith("6.6.")
           and lines[0].endswith("-virt"), r.as_dict())
    record("one_vcpu", len(lines) > 1 and lines[1] == "1", lines[:2])
    record("memory_capped", len(lines) > 2 and int(lines[2].split()[1]) < 128 * 1024,
           lines[2:3])
    record("no_network_device", len(lines) > 3 and lines[3] == "lo"
           and all(x == "lo" for x in lines[3:]), lines[3:])

    marker = os.path.join(tempfile.gettempdir(), "cgt_host_secret_ci.txt")
    with open(marker, "w", encoding="utf-8") as f:
        f.write("HOST_SECRET_MUST_NOT_LEAK")
    r = QemuMicroVm(a, timeout_s=20).run(
        "cat %s 2>/dev/null || echo ABSENT; ls /home | wc -l" % marker)
    record("host_file_invisible",
           r.ok and "ABSENT" in r.stdout and "HOST_SECRET_MUST_NOT_LEAK" not in r.stdout,
           r.stdout)
    os.remove(marker)

    r = QemuMicroVm(a, timeout_s=20).run(
        "echo STATE > /tmp/cgt_state; cat /tmp/cgt_state")
    r2 = QemuMicroVm(a, timeout_s=20).run(
        "cat /tmp/cgt_state 2>/dev/null || echo NO_STATE")
    record("one_shot_rootfs", r.ok and r2.ok and "STATE" in r.stdout
           and "NO_STATE" in r2.stdout, [r.stdout, r2.stdout])

    r = QemuMicroVm(a, timeout_s=2).run("echo BEFORE; sleep 9; echo AFTER")
    record("wall_timeout_kill", (not r.ok) and r.timed_out and "BEFORE" in r.stdout
           and "AFTER" not in r.stdout, r.as_dict())

    f = QemuMicroVmFactory(a, hard_mem_mb=256, hard_vcpu=2, hard_wall_ms=20000)
    quota_ok = True
    for req in ({"mem_mb": 512}, {"vcpu": 4}, {"wall_ms": 20001}):
        try:
            f(req)
            quota_ok = False
        except MicroVmQuotaError:
            pass
    record("hard_quota_reject", quota_ok, "mem/vcpu/wall")

    cmd = r.command
    joined = " ".join(cmd)
    forbidden = [x for x in ("-drive", "-virtfs", "-netdev", "-fsdev", "-hda")
                 if x in cmd]
    record("no_host_backends", not forbidden,
           {"forbidden": forbidden,
            "machine": "microvm" if "-machine microvm" in joined else "?"})
    record("tcg_accel", any("accel=tcg" in str(x) for x in cmd), "tcg")

    evidence["ok"] = all(t["ok"] for t in evidence["tests"])
    evidence["host_kernel"] = os.uname().release
    evidence["runner"] = {"GITHUB_ACTIONS": os.environ.get("GITHUB_ACTIONS"),
                          "GITHUB_RUN_ID": os.environ.get("GITHUB_RUN_ID"),
                          "GITHUB_SHA": os.environ.get("GITHUB_SHA")}
    print("CGT_EVIDENCE=" + json.dumps(evidence, ensure_ascii=False, sort_keys=True))
    return 0 if evidence["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
