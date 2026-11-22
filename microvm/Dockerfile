FROM alpine:3.20.3

# QEMU microvm machine + Alpine virt kernel; assets baked into the image.
RUN set -eux; \
    apk add --no-cache qemu-system-x86 busybox-static wget ca-certificates; \
    mkdir -p /opt/cgt-microvm/bin /opt/cgt-microvm/kernel \
             /opt/cgt-microvm/root/usr/lib/x86_64-linux-gnu \
             /opt/cgt-microvm/root/usr/share; \
    cp "$(command -v qemu-system-x86_64)" /opt/cgt-microvm/bin/; \
    cp /bin/busybox.static /opt/cgt-microvm/bin/busybox; \
    chmod +x /opt/cgt-microvm/bin/*; \
    ln -s /usr/share/qemu /opt/cgt-microvm/root/usr/share/qemu; \
    if [ -d /usr/lib/qemu ]; then \
      ln -s /usr/lib/qemu /opt/cgt-microvm/root/usr/lib/x86_64-linux-gnu/qemu; \
    elif [ -d /usr/lib/x86_64-linux-gnu/qemu ]; then \
      ln -s /usr/lib/x86_64-linux-gnu/qemu /opt/cgt-microvm/root/usr/lib/x86_64-linux-gnu/qemu; \
    else \
      echo "qemu module dir not found"; exit 1; \
    fi; \
    ln -s /usr/lib /opt/cgt-microvm/root/lib; \
    wget -q -O /opt/cgt-microvm/kernel/vmlinuz-virt \
      https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/netboot/vmlinuz-virt; \
    test -s /opt/cgt-microvm/kernel/vmlinuz-virt; \
    test -f /opt/cgt-microvm/root/usr/share/qemu/bios-microvm.bin; \
    qemu-system-x86_64 --version

ENV CGT_MICROVM_HOME=/opt/cgt-microvm
WORKDIR /app
COPY cg_tz_microvm_runtime.py /app/
COPY verify_microvm.py /app/

CMD ["python3", "/app/verify_microvm.py"]
