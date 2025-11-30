#!/usr/bin/env bash
set -euo pipefail

APX_VERSION="${APX_VERSION:-0.1.0}"
APX_ARCH="${APX_ARCH:-arm64}"

echo "Installing APX CLI v${APX_VERSION} for darwin/${APX_ARCH}..."

DOWNLOAD_URL="https://github.com/apx-project/apx-cli/releases/download/v${APX_VERSION}/apx-darwin-${APX_ARCH}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

curl -fsSL "${DOWNLOAD_URL}" -o "${TMP_DIR}/apx"
chmod +x "${TMP_DIR}/apx"
sudo mv "${TMP_DIR}/apx" /usr/local/bin/apx

echo "APX CLI installed: $(/usr/local/bin/apx --version || echo 'placeholder build, version unavailable')"

