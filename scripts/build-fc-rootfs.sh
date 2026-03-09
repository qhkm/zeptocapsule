#!/usr/bin/env bash
# build-fc-rootfs.sh — Create a minimal ext4 rootfs image for Firecracker tests.
#
# The image contains a minimal Alpine/busybox user-space (/bin/sh, /bin/cat,
# /bin/sleep, etc.) that is enough for the integration tests. The zk-init
# binary is NOT embedded here; the Firecracker backend stages it into the
# rootfs copy at runtime via stage_firecracker_payload().
#
# Usage:  ./scripts/build-fc-rootfs.sh [output-path]
# Default output: ./artifacts/rootfs.ext4
#
# Requires: root (or fakeroot), losetup, mkfs.ext4, mount, wget/curl.
set -euo pipefail

ROOTFS_SIZE_MB=128
ALPINE_MINI_ROOTFS_URL="https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/alpine-minirootfs-3.21.3-x86_64.tar.gz"
OUTPUT="${1:-./artifacts/rootfs.ext4}"
WORK_DIR="$(mktemp -d /tmp/zk-rootfs-build.XXXXXX)"

cleanup() {
    if mountpoint -q "$WORK_DIR/mnt" 2>/dev/null; then
        umount "$WORK_DIR/mnt" || true
    fi
    if [ -n "${LOOP_DEV:-}" ]; then
        losetup -d "$LOOP_DEV" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

echo "==> Creating ${ROOTFS_SIZE_MB}MB ext4 image at $OUTPUT"
mkdir -p "$(dirname "$OUTPUT")"
dd if=/dev/zero of="$OUTPUT" bs=1M count="$ROOTFS_SIZE_MB" status=progress
mkfs.ext4 -F -L zk-rootfs "$OUTPUT"

echo "==> Mounting image"
mkdir -p "$WORK_DIR/mnt"
LOOP_DEV="$(losetup --find --show "$OUTPUT")"
mount "$LOOP_DEV" "$WORK_DIR/mnt"

echo "==> Downloading Alpine minirootfs"
TARBALL="$WORK_DIR/alpine.tar.gz"
if command -v wget >/dev/null 2>&1; then
    wget -q -O "$TARBALL" "$ALPINE_MINI_ROOTFS_URL"
else
    curl -fsSL -o "$TARBALL" "$ALPINE_MINI_ROOTFS_URL"
fi

echo "==> Extracting rootfs"
tar xzf "$TARBALL" -C "$WORK_DIR/mnt"

echo "==> Creating required directories"
mkdir -p "$WORK_DIR/mnt"/{proc,sys,dev,tmp,run/zeptocapsule,workspace,sbin}

# Ensure /sbin/init is a placeholder (will be replaced by zk-init at runtime)
if [ ! -f "$WORK_DIR/mnt/sbin/init" ]; then
    echo '#!/bin/sh' > "$WORK_DIR/mnt/sbin/init"
    echo 'echo "ERROR: zk-init not staged"; exec /bin/sh' >> "$WORK_DIR/mnt/sbin/init"
    chmod 755 "$WORK_DIR/mnt/sbin/init"
fi

# Create minimal /dev nodes for console
mknod -m 622 "$WORK_DIR/mnt/dev/console" c 5 1 2>/dev/null || true
mknod -m 666 "$WORK_DIR/mnt/dev/null"    c 1 3 2>/dev/null || true
mknod -m 666 "$WORK_DIR/mnt/dev/zero"    c 1 5 2>/dev/null || true

echo "==> Unmounting"
umount "$WORK_DIR/mnt"
losetup -d "$LOOP_DEV"
unset LOOP_DEV

echo "==> rootfs image ready: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
