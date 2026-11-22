# cgt-microvm-ci-evidence

常工-天智 ①-8「MicroVM 真隔离、远端 GitHub Actions 实跑」的最小远端验证夹具。

- 镜像内固定 QEMU `microvm` 机器 + Alpine virt 内核 + 静态 busybox；
- 客户机不挂宿主目录、无网卡（`-nic none`）、独立内核、一次性根文件系统；
- `-m 128 -smp 1` 硬配额，wall timeout 进程组硬杀；
- 输出 `CGT_EVIDENCE=` JSON，含资产 SHA-256 与逐项断言结果。

本地等价运行（Linux，资产由镜像提供）：

```bash
docker build -t cgt-microvm-ci ./microvm
docker run --rm cgt-microvm-ci
```

Workflow：`.github/workflows/microvm.yml`（push / workflow_dispatch）。
