# Firecracker Deployment Guide

How to build, ship, and run ZeptoCapsule's Firecracker backend in production.

## Artifacts Required

The Firecracker backend needs three artifacts at runtime:

| Artifact | Description | Default path |
|----------|-------------|--------------|
| `firecracker` | Firecracker VMM binary | `/usr/bin/firecracker` or `/usr/local/bin/firecracker` |
| `vmlinux` | Uncompressed Linux kernel | Configured in `FirecrackerConfig.kernel_path` |
| `rootfs.ext4` | Guest root filesystem image | Configured in `FirecrackerConfig.rootfs_path` |

The `zk-init` binary is **not** embedded in the rootfs — it is staged into a copy at runtime by `stage_firecracker_payload()`.

## Host Requirements

- Linux with `/dev/kvm` (bare metal or nested-virt-enabled VM)
- Firecracker binary installed
- Enough disk for rootfs copies (128MB per capsule, cleaned up on destroy)

## 1. Build the Kernel

Firecracker needs an uncompressed `vmlinux` (not `bzImage`). You can either download a pre-built one or compile from source.

### Option A: Download Pre-Built (Recommended)

Firecracker publishes tested kernels:

```bash
KERNEL_VERSION="5.10.225"
curl -fsSL -o vmlinux \
  "https://s3.amazonaws.com/spec.ccfc.min/ci-artifacts/kernels/x86_64/vmlinux-${KERNEL_VERSION}"
```

For aarch64:
```bash
curl -fsSL -o vmlinux \
  "https://s3.amazonaws.com/spec.ccfc.min/ci-artifacts/kernels/aarch64/vmlinux-${KERNEL_VERSION}"
```

### Option B: Build from Source

```bash
git clone --depth 1 --branch v5.10.225 https://github.com/torvalds/linux.git
cd linux

# Use Firecracker's recommended config
curl -fsSL -o .config \
  "https://s3.amazonaws.com/spec.ccfc.min/ci-artifacts/kernels/x86_64/vmlinux-${KERNEL_VERSION}.config"

make vmlinux -j$(nproc)
# Output: vmlinux (uncompressed, ~30MB)
```

## 2. Build the Rootfs

### Using the Provided Script

```bash
# Requires root (or run inside Docker)
sudo ./scripts/build-fc-rootfs.sh /var/lib/zeptocapsule/rootfs.ext4
```

This creates a 128MB ext4 image with Alpine minirootfs containing:
- `/bin/sh`, `/bin/cat`, `/bin/sleep`, etc. (busybox)
- `/dev/console`, `/dev/null`, `/dev/zero`
- `/run/zeptocapsule/` (staging directory for zk-init)
- `/workspace/` (mount point for workspace)
- `/sbin/init` placeholder (replaced by `zk-init` at runtime)

### Custom Rootfs

If you need additional tools (Python, Node, etc.):

```bash
# Start from the Alpine base
sudo ./scripts/build-fc-rootfs.sh /tmp/base-rootfs.ext4

# Mount and customize
sudo mkdir -p /mnt/rootfs
sudo mount -o loop /tmp/base-rootfs.ext4 /mnt/rootfs

# Install packages via chroot
sudo chroot /mnt/rootfs apk add --no-cache python3 nodejs

sudo umount /mnt/rootfs
mv /tmp/base-rootfs.ext4 /var/lib/zeptocapsule/rootfs.ext4
```

For larger workloads, increase image size by editing `ROOTFS_SIZE_MB` in the script.

## 3. Build zk-init

The init shim must be statically linked (runs as PID 1 inside the VM):

```bash
# Install musl target
rustup target add x86_64-unknown-linux-musl

# Build static binary
cargo build --bin zk-init --target x86_64-unknown-linux-musl --release

# Output: target/x86_64-unknown-linux-musl/release/zk-init (~5MB)
```

For aarch64:
```bash
rustup target add aarch64-unknown-linux-musl
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
  cargo build --bin zk-init --target aarch64-unknown-linux-musl --release
```

The binary path is resolved at runtime via:
1. `CapsuleSpec.init_binary` (explicit)
2. `ZEPTOCAPSULE_INIT_BINARY` env var
3. `{exe_dir}/zk-init` (relative to the calling binary)

## 4. Deploy Artifacts

### Standard Layout

```
/var/lib/zeptocapsule/
  vmlinux          # kernel
  rootfs.ext4      # base rootfs image
/usr/local/bin/
  firecracker      # VMM binary
  zk-init          # init shim (or alongside your app binary)
```

### Configure in ZeptoPM

```toml
# zeptopm.toml
[daemon]
isolation = "firecracker"

[daemon.firecracker]
firecracker_bin = "/usr/local/bin/firecracker"
kernel_path = "/var/lib/zeptocapsule/vmlinux"
rootfs_path = "/var/lib/zeptocapsule/rootfs.ext4"
```

### Configure Programmatically

```rust
let spec = CapsuleSpec {
    isolation: Isolation::Firecracker,
    firecracker: Some(FirecrackerConfig {
        firecracker_bin: PathBuf::from("/usr/local/bin/firecracker"),
        kernel_path: PathBuf::from("/var/lib/zeptocapsule/vmlinux"),
        rootfs_path: PathBuf::from("/var/lib/zeptocapsule/rootfs.ext4"),
        vcpus: Some(2),
        memory_mib: Some(512),
        enable_network: false,
        tap_name: None,
    }),
    ..Default::default()
};
```

## 5. Runtime Flow

When `zeptocapsule::create(spec)` runs with Firecracker isolation:

1. Creates a state directory under `/tmp/zk-fc-*`
2. Copies `rootfs.ext4` to state dir (writable copy)
3. Stages `zk-init` into the rootfs copy at `/sbin/init`
4. Stages the worker binary at `/run/zeptocapsule/worker`
5. Writes worker args and env to `/run/zeptocapsule/worker.args` and `worker.env`
6. Starts Firecracker with the configured kernel + rootfs
7. `zk-init` (PID 1 in guest) reads the staged config, sets up `/proc`, `/dev`, then `execve`s the worker
8. Host communicates with guest via vsock (ports 1001-1004 for stdin/stdout/stderr/control)
9. On destroy: sends TERMINATE via control channel, waits, then kills VM

## 6. Verify the Setup

### Run Integration Tests

```bash
# Env vars for test discovery
export ZK_FC_KERNEL=/var/lib/zeptocapsule/vmlinux
export ZK_FC_ROOTFS=/var/lib/zeptocapsule/rootfs.ext4

# Run Firecracker tests (needs root for /dev/kvm)
sudo -E env ZK_RUN_FIRECRACKER_TESTS=1 \
  cargo test --test firecracker_backend -- --test-threads=1 --nocapture
```

### Using Docker (Recommended for CI)

```bash
./scripts/test-firecracker.sh         # FC tests only
./scripts/test-firecracker.sh --all   # namespace + FC tests
```

Requires a Linux host with `/dev/kvm` — Docker Desktop on macOS will not work.

### Manual Smoke Test

```bash
# Inside Docker or on a KVM host
./scripts/manual-fc-test.sh
```

## 7. Artifact Versioning

For production, version your artifacts alongside your release:

```
releases/v0.1.0/
  zk-init-x86_64
  zk-init-aarch64
  rootfs-x86_64.ext4
  rootfs-aarch64.ext4
  vmlinux-5.10.225-x86_64
  vmlinux-5.10.225-aarch64
```

The rootfs image is architecture-specific (Alpine packages differ). The kernel must match the target architecture.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `KernelError::SpawnFailed` on create | `/dev/kvm` not available | Run on bare metal or nested-virt VM |
| VM boots but worker doesn't start | `zk-init` not staged correctly | Check `zk-init` is statically linked: `file zk-init` should show "statically linked" |
| `init_error: "execve /sbin/init: ENOEXEC"` | Dynamic `zk-init` in static-only guest | Rebuild with `--target x86_64-unknown-linux-musl` |
| Workspace files not visible | rootfs too small for workspace copy | Increase `ROOTFS_SIZE_MB` or use `workspace.size_mib` in spec |
| `Transport("vsock connect...")` | Guest hasn't booted yet | Firecracker backend retries for 30s; if still failing, check serial log in state dir |
