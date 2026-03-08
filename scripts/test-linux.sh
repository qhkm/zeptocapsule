#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE="zeptokernel-dev"

# Verify Docker daemon is running
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker daemon is not running. Start Docker Desktop and retry." >&2
    exit 1
fi

echo "==> Building Docker image..."
docker build -t "$IMAGE" -f "$PROJECT_ROOT/Dockerfile.dev" "$PROJECT_ROOT"

echo "==> Running tests inside Docker..."
# Mount /workspace/target as a Docker-managed named volume so Linux build
# artefacts are isolated from macOS build artefacts (both hosts are aarch64).
# The integration tests hard-code target/debug/{zk-guest,mock-worker}, so we
# shadow the macOS target/ with the Docker volume and build binaries first.
# --privileged is required for Linux namespace syscalls (clone CLONE_NEWNS etc.)
docker run --rm \
    --privileged \
    -v "$PROJECT_ROOT:/workspace" \
    -v "zeptokernel-target:/workspace/target" \
    -v "$HOME/.cargo/registry:/usr/local/cargo/registry" \
    -v "$HOME/.cargo/git:/usr/local/cargo/git" \
    -w /workspace \
    "$IMAGE" \
    bash -c "cargo build --workspace && cargo test --workspace --features namespace"
