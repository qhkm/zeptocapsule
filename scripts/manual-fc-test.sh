#!/usr/bin/env bash
set -euo pipefail

# Manual Firecracker boot test to diagnose guest init behavior.
# Run inside the Docker container.

cargo build --bin zk-init --target x86_64-unknown-linux-musl 2>/dev/null

WD=/tmp/fc-manual
rm -rf "$WD"
mkdir -p "$WD"

echo "==> Preparing rootfs"
cp "$ZK_FC_ROOTFS" "$WD/rootfs.ext4"
mkdir -p "$WD/rootfs_mount"
mount -o loop "$WD/rootfs.ext4" "$WD/rootfs_mount"

mkdir -p "$WD/rootfs_mount/run/zeptocapsule"
# Remove symlink first (Alpine /sbin/init -> /bin/busybox)
rm -f "$WD/rootfs_mount/sbin/init"
cp target/x86_64-unknown-linux-musl/debug/zk-init "$WD/rootfs_mount/sbin/init"
chmod 755 "$WD/rootfs_mount/sbin/init"

cp /bin/cat "$WD/rootfs_mount/run/zeptocapsule/worker"
chmod 755 "$WD/rootfs_mount/run/zeptocapsule/worker"

printf '/run/zeptocapsule/worker\n' > "$WD/rootfs_mount/run/zeptocapsule/worker.path"
printf '1\n' > "$WD/rootfs_mount/run/zeptocapsule/firecracker.mode"

echo "Staged files:"
ls -la "$WD/rootfs_mount/sbin/init"
file "$WD/rootfs_mount/sbin/init"
ls -la "$WD/rootfs_mount/run/zeptocapsule/"

umount "$WD/rootfs_mount"

echo "==> Starting Firecracker"
touch "$WD/log"
/opt/firecracker/firecracker \
    --api-sock "$WD/api.sock" \
    --log-path "$WD/log" \
    --level Info &
FC_PID=$!
sleep 1

echo "==> Configuring VM"
curl -s --unix-socket "$WD/api.sock" -X PUT "http://localhost/machine-config" \
    -H "Content-Type: application/json" \
    -d '{"vcpu_count":1,"mem_size_mib":128}'
echo ""

curl -s --unix-socket "$WD/api.sock" -X PUT "http://localhost/boot-source" \
    -H "Content-Type: application/json" \
    -d '{"kernel_image_path":"/opt/firecracker/vmlinux","boot_args":"console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/sbin/init"}'
echo ""

curl -s --unix-socket "$WD/api.sock" -X PUT "http://localhost/drives/rootfs" \
    -H "Content-Type: application/json" \
    -d "{\"drive_id\":\"rootfs\",\"path_on_host\":\"$WD/rootfs.ext4\",\"is_root_device\":true,\"is_read_only\":false}"
echo ""

echo "==> Booting VM"
curl -s --unix-socket "$WD/api.sock" -X PUT "http://localhost/actions" \
    -H "Content-Type: application/json" \
    -d '{"action_type":"InstanceStart"}'
echo ""

echo "==> Waiting 8 seconds for boot..."
sleep 8

echo "=== Firecracker log ==="
cat "$WD/log"
echo "=== end log ==="

kill $FC_PID 2>/dev/null || true
wait $FC_PID 2>/dev/null || true
