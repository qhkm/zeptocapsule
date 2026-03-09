#!/usr/bin/env bash
# test-firecracker.sh — Build the Firecracker test image and run integration tests.
#
# Requirements:
#   - Linux host with /dev/kvm (NOT macOS Docker Desktop)
#   - Docker installed
#
# Usage:
#   ./scripts/test-firecracker.sh              # run FC tests only
#   ./scripts/test-firecracker.sh --all        # run all tests (namespace + FC)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE="zeptocapsule-fc"

# --- Pre-flight checks ---

if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker daemon is not running." >&2
    exit 1
fi

# Check for /dev/kvm on the host
if [ ! -c /dev/kvm ]; then
    echo "ERROR: /dev/kvm not found." >&2
    echo "" >&2
    echo "Firecracker requires hardware KVM. This script must run on a" >&2
    echo "Linux host with KVM support — not inside Docker Desktop on macOS." >&2
    echo "" >&2
    echo "Options:" >&2
    echo "  1. Run on a Linux machine / VM with KVM" >&2
    echo "  2. Use a CI runner with KVM (GitHub Actions larger runners," >&2
    echo "     GitLab KVM runners, Hetzner Cloud, etc.)" >&2
    exit 1
fi

# --- Build ---

echo "==> Building Firecracker test image..."
docker build -t "$IMAGE" -f "$PROJECT_ROOT/Dockerfile.firecracker" "$PROJECT_ROOT"

# --- Run ---

RUN_ALL="${1:-}"
if [ "$RUN_ALL" = "--all" ]; then
    TEST_ENV="ZK_RUN_NAMESPACE_TESTS=1 ZK_RUN_FIRECRACKER_TESTS=1"
    echo "==> Running ALL tests (namespace + firecracker)..."
else
    TEST_ENV="ZK_RUN_FIRECRACKER_TESTS=1"
    echo "==> Running Firecracker integration tests..."
fi

# --privileged: needed for mount, cgroup, namespace syscalls
# --device /dev/kvm: pass through KVM to the container
# Named volume for target/ so Linux build artifacts stay isolated
docker run --rm \
    --privileged \
    --device /dev/kvm \
    -v "$PROJECT_ROOT:/workspace" \
    -v "zeptocapsule-fc-target:/workspace/target" \
    -v "$HOME/.cargo/registry:/usr/local/cargo/registry" \
    -v "$HOME/.cargo/git:/usr/local/cargo/git" \
    -w /workspace \
    "$IMAGE" \
    bash -c "cargo build --bin zk-init --target x86_64-unknown-linux-musl && ZK_FC_INIT_BIN=/workspace/target/x86_64-unknown-linux-musl/debug/zk-init $TEST_ENV cargo test --workspace -- --test-threads=1"
