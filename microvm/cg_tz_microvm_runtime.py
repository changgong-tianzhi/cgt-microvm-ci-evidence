# -*- coding: utf-8 -*-
"""
常工-天智 MicroVM 真实隔离执行层 v1.0
=====================================
QEMU `microvm` 机器类型的真实系统级虚拟机执行器：
  - 独立内核（Alpine virt）+ 独立 initramfs 根文件系统，一次性启动、用完即毁；
  - 不挂载宿主目录、不加任何 `-drive`/`-virtfs`，客户机看不到宿主文件；
  - `-nic none`，客户机无网卡、无网络出口；
  - `-m`/`-smp` 硬配额，外层 wall timeout；
  - 无 `/dev/kvm` 时用 QEMU TCG 软件虚拟化（性能低，但隔离真实）；
  - 命令以源文件形式注入 initramfs 的 `/payload.sh`，不拼接 shell 参数。
"""
from __future__ import annotations

import json
import os
import platform
import select
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_BEGIN = "CGT_GUEST_BEGIN"
_END = "CGT_GUEST_END"
_RC = "CGT_GUEST_RC="


class MicroVmUnavailable(RuntimeError):
    """运行资产缺失或平台不支持。"""


class MicroVmQuotaError(RuntimeError):
    """请求超出硬配额。"""


def _sha256_file(path: str) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class MicroVmAssets:
    """一套已解包的 microVM 运行资产。"""

    root: str
    qemu: str
    kernel: str
    busybox: str
    data_dir: str
    module_dir: str
    lib_dirs: List[str] = field(default_factory=list)
    accel: str = "tcg"

    def missing(self) -> List[str]:
        miss: List[str] = []
        if not (os.path.isfile(self.qemu) and os.access(self.qemu, os.X_OK)):
            miss.append("qemu")
        if not os.path.isfile(self.kernel):
            miss.append("kernel")
        if not (os.path.isfile(self.busybox) and os.access(self.busybox, os.X_OK)):
            miss.append("busybox")
        if not os.path.isfile(os.path.join(self.data_dir, "bios-microvm.bin")):
            miss.append("bios-microvm.bin")
        if not os.path.isdir(self.module_dir):
            miss.append("qemu-modules")
        for d in self.lib_dirs:
            if not os.path.isdir(d):
                miss.append("lib:" + d)
        return miss

    @property
    def available(self) -> bool:
        return not self.missing()

    def env(self) -> Dict[str, str]:
        e = dict(os.environ)
        e["LD_LIBRARY_PATH"] = os.pathsep.join(self.lib_dirs)
        e["QEMU_MODULE_DIR"] = self.module_dir
        return e

    def manifest(self) -> Dict[str, Any]:
        files = {}
        for key, path in (("qemu", self.qemu), ("kernel", self.kernel),
                          ("busybox", self.busybox)):
            if os.path.isfile(path):
                files[key] = {
                    "path": os.path.relpath(path, self.root),
                    "size": os.path.getsize(path),
                    "sha256": _sha256_file(path),
                }
        return {
            "root": self.root,
            "platform": platform.system().lower(),
            "accel": self.accel,
            "files": files,
            "available": self.available,
            "missing": self.missing(),
        }

    @classmethod
    def discover(cls, root: Optional[str] = None) -> "MicroVmAssets":
        """按 CGT_MICROVM_HOME / 约定布局发现运行资产。"""
        root = root or os.environ.get("CGT_MICROVM_HOME") or "/opt/cgt-microvm"
        root = os.path.abspath(root)
        lib_root = os.path.join(root, "root")
        lib_dirs = [
            os.path.join(lib_root, "usr", "lib", "x86_64-linux-gnu"),
            os.path.join(lib_root, "lib", "x86_64-linux-gnu"),
        ]
        accel = "kvm" if os.path.exists("/dev/kvm") else "tcg"
        return cls(
            root=root,
            qemu=os.environ.get("CGT_QEMU_BIN")
            or os.path.join(root, "bin", "qemu-system-x86_64"),
            kernel=os.environ.get("CGT_QEMU_KERNEL")
            or os.path.join(root, "kernel", "vmlinuz-virt"),
            busybox=os.environ.get("CGT_QEMU_BUSYBOX")
            or os.path.join(root, "bin", "busybox"),
            data_dir=os.environ.get("CGT_QEMU_DATA_DIR")
            or os.path.join(lib_root, "usr", "share", "qemu"),
            module_dir=os.environ.get("CGT_QEMU_MODULE_DIR")
            or os.path.join(lib_root, "usr", "lib", "x86_64-linux-gnu", "qemu"),
            lib_dirs=lib_dirs,
            accel=accel,
        )


@dataclass
class MicroVmResult:
    ok: bool
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    elapsed_ms: int
    vm_id: str
    accel: str
    memory_mb: int
    vcpus: int
    command: List[str]
    truncated: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "elapsed_ms": self.elapsed_ms,
            "vm_id": self.vm_id,
            "accel": self.accel,
            "memory_mb": self.memory_mb,
            "vcpus": self.vcpus,
            "truncated": self.truncated,
        }


def _applet_links(busybox: str, bin_dir: str) -> None:
    out = subprocess.run([busybox, "--list"], capture_output=True, text=True, check=True)
    for applet in out.stdout.split():
        if not applet or applet == "busybox":
            continue
        link = os.path.join(bin_dir, applet)
        if not os.path.lexists(link):
            os.symlink("busybox", link)


def _build_initramfs(assets: MicroVmAssets, script: str) -> Tuple[str, str]:
    """构造一次性 initramfs；脚本以 /payload.sh 注入，不拼接 shell 参数。"""
    tmp = tempfile.mkdtemp(prefix="cgt_microvm_")
    root = os.path.join(tmp, "rootfs")
    for d in ("bin", "dev", "proc", "sys", "tmp", "etc"):
        os.makedirs(os.path.join(root, d), exist_ok=True)
    shutil.copy2(assets.busybox, os.path.join(root, "bin", "busybox"))
    _applet_links(assets.busybox, os.path.join(root, "bin"))

    with open(os.path.join(root, "payload.sh"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write(script)

    init = """#!/bin/sh
export PATH=/bin
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
echo "%s"
if [ -f /payload.sh ]; then
  ( . /payload.sh )
  rc=$?
else
  echo "cgt: payload missing"
  rc=125
fi
echo "%s$rc"
echo "%s"
sync
exit 0
""" % (_BEGIN, _RC, _END)
    with open(os.path.join(root, "init"), "w", encoding="utf-8", newline="\n") as f:
        f.write(init)
    os.chmod(os.path.join(root, "init"), 0o755)

    cpio_path = os.path.join(tmp, "initramfs.cpio")
    out_f = open(cpio_path, "wb")
    find = subprocess.Popen(["find", ".", "-print"], cwd=root,
                            stdout=subprocess.PIPE)
    proc = subprocess.Popen([assets.busybox, "cpio", "-o", "-H", "newc"],
                            cwd=root, stdin=find.stdout,
                            stdout=out_f, stderr=subprocess.PIPE)
    find.stdout.close()
    _, err = proc.communicate(timeout=30)
    out_f.close()
    find.wait(timeout=5)
    if proc.returncode != 0:
        raise MicroVmUnavailable("initramfs build failed: %r" % (err[-300:],))
    return tmp, cpio_path


class QemuMicroVm:
    """一次性 QEMU microVM 会话：run() 启动、结束后进程与根目录一并销毁。"""

    def __init__(self, assets: MicroVmAssets, *,
                 memory_mb: int = 128, vcpus: int = 1,
                 timeout_s: float = 10.0, max_output_bytes: int = 64 * 1024,
                 accel: Optional[str] = None) -> None:
        self.assets = assets
        self.memory_mb = int(memory_mb)
        self.vcpus = max(1, int(vcpus))
        self.timeout_s = float(timeout_s)
        self.max_output_bytes = int(max_output_bytes)
        self.accel = accel or assets.accel
        self._vm_id = "vm-%d-%d" % (os.getpid(), int(time.time() * 1000))

    def _command(self, initrd: str, monitor_sock: str) -> List[str]:
        return [
            self.assets.qemu,
            "-L", self.assets.data_dir,
            "-machine", "microvm,accel=" + self.accel,
            "-m", str(self.memory_mb),
            "-smp", str(self.vcpus),
            "-kernel", self.assets.kernel,
            "-initrd", initrd,
            "-append", "console=ttyS0 panic=1 quiet",
            "-nographic",
            "-no-reboot",
            "-nic", "none",
            "-monitor", "unix:%s,server=on,wait=off" % monitor_sock,
        ]

    def run(self, script: str) -> MicroVmResult:
        missing = self.assets.missing()
        if missing:
            raise MicroVmUnavailable("microVM assets missing: " + ", ".join(missing))
        tmp, initrd = _build_initramfs(self.assets, script)
        monitor_sock = os.path.join(tmp, "mon.sock")
        cmd = self._command(initrd, monitor_sock)
        started = time.time()
        timed_out = False
        completed = False
        buf = b""
        proc = None
        try:
            proc = subprocess.Popen(
                cmd, env=self.assets.env(), stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                start_new_session=True)
            deadline = started + self.timeout_s
            while True:
                if time.time() > deadline:
                    timed_out = True
                    break
                ready, _, _ = select.select([proc.stdout], [], [], 0.05)
                if ready:
                    chunk = os.read(proc.stdout.fileno(), 8192)
                    if not chunk:
                        break
                    buf += chunk
                    if _END.encode("ascii") in buf:
                        completed = True
                        drain_until = time.time() + 0.2
                        while time.time() < drain_until:
                            rr, _, _ = select.select([proc.stdout], [], [], 0.05)
                            if not rr:
                                continue
                            more = os.read(proc.stdout.fileno(), 8192)
                            if not more:
                                break
                            buf += more
                        break
                    if len(buf) > 4 * 1024 * 1024:
                        buf = buf[-1024 * 1024:]
                elif proc.poll() is not None:
                    break
        finally:
            if proc is not None:
                if not timed_out and completed:
                    self._monitor_quit(monitor_sock, proc)
                if timed_out:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except Exception:
                        proc.kill()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()
                if proc.stdout:
                    proc.stdout.close()
            shutil.rmtree(tmp, ignore_errors=True)

        elapsed = int((time.time() - started) * 1000)
        out, rc, truncated = self._parse(buf.decode("utf-8", "replace"))
        return MicroVmResult(
            ok=(completed and not timed_out and rc == 0),
            exit_code=rc,
            stdout=out,
            stderr="" if not out else "",
            timed_out=timed_out,
            elapsed_ms=elapsed,
            vm_id=self._vm_id,
            accel=self.accel,
            memory_mb=self.memory_mb,
            vcpus=self.vcpus,
            command=cmd,
            truncated=truncated,
        )

    @staticmethod
    def _monitor_quit(monitor_sock: str, proc: subprocess.Popen) -> None:
        """用 QEMU monitor 正常退出，避免 microvm 在 init 结束后不自退。"""
        deadline = time.time() + 1.0
        while time.time() < deadline:
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect(monitor_sock)
                s.sendall(b"quit\n")
                s.close()
                proc.wait(timeout=1.5)
                return
            except Exception:
                time.sleep(0.05)
        try:
            proc.terminate()
        except Exception:
            pass

    def _parse(self, raw: str) -> Tuple[str, int, bool]:
        start = raw.find(_BEGIN)
        if start < 0:
            return raw[-self.max_output_bytes:], 124, len(raw) > self.max_output_bytes
        body = raw[start + len(_BEGIN):]
        rc_pos = body.find(_RC)
        end_pos = body.find(_END)
        if rc_pos < 0 or end_pos < 0 or end_pos < rc_pos:
            text = body[-self.max_output_bytes:]
            return text, 124, len(body) > self.max_output_bytes
        text = body[:rc_pos]
        text = text.lstrip("\r\n")
        try:
            rc = int(body[rc_pos + len(_RC):end_pos].strip().splitlines()[0])
        except Exception:
            rc = 124
        if text.startswith("\n"):
            text = text[1:]
        truncated = len(text) > self.max_output_bytes
        if truncated:
            text = text[-self.max_output_bytes:]
        return text, rc, truncated

    @property
    def vm_id(self) -> str:
        return self._vm_id


class QemuMicroVmFactory:
    """可注入 `CgTzIsolationProbe.bind_vm_factory` 的真实 VM 工厂。"""

    def __init__(self, assets: Optional[MicroVmAssets] = None, *,
                 hard_mem_mb: int = 1024, hard_vcpu: int = 2,
                 hard_wall_ms: int = 10000, default_timeout_s: float = 10.0,
                 accel: Optional[str] = None) -> None:
        self.assets = assets or MicroVmAssets.discover()
        self.hard_mem_mb = hard_mem_mb
        self.hard_vcpu = hard_vcpu
        self.hard_wall_ms = hard_wall_ms
        self.default_timeout_s = default_timeout_s
        self.accel = accel

    @property
    def available(self) -> bool:
        return self.assets.available

    def __call__(self, req: Dict[str, Any]) -> QemuMicroVm:
        mem = int(float(req.get("mem_mb", 128)))
        vcpu = int(float(req.get("vcpu", 1)))
        wall = float(req.get("wall_ms", self.hard_wall_ms))
        if mem > self.hard_mem_mb:
            raise MicroVmQuotaError("mem quota exceeded: %s > %s" % (mem, self.hard_mem_mb))
        if vcpu > self.hard_vcpu:
            raise MicroVmQuotaError("vcpu quota exceeded: %s > %s" % (vcpu, self.hard_vcpu))
        if wall > self.hard_wall_ms:
            raise MicroVmQuotaError("wall quota exceeded: %s > %s" % (wall, self.hard_wall_ms))
        if not self.available:
            raise MicroVmUnavailable("microVM assets missing: " +
                                     ", ".join(self.assets.missing()))
        return QemuMicroVm(
            self.assets, memory_mb=mem, vcpus=vcpu,
            timeout_s=min(self.default_timeout_s, wall / 1000.0) or self.default_timeout_s,
            accel=self.accel)


if __name__ == "__main__":
    a = MicroVmAssets.discover()
    print(json.dumps(a.manifest(), ensure_ascii=False, indent=2))
