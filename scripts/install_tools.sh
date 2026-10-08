#!/usr/bin/env bash
# Installs the scanner CLIs on a Linux CI runner / container, with pinned versions and checksum verification.
set -euo pipefail
TRIVY_VERSION="${TRIVY_VERSION:-0.74.0}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"
BIN="${BIN_DIR:-/usr/local/bin}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

echo "::group::trivy ${TRIVY_VERSION}"
base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"
curl -fsSLO "${base}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
curl -fsSLO "${base}/trivy_${TRIVY_VERSION}_checksums.txt"
grep " trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -
tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" trivy && install -m 0755 trivy "$BIN/trivy"
echo "::endgroup::"

echo "::group::gitleaks ${GITLEAKS_VERSION}"
base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"
curl -fsSLO "${base}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
curl -fsSLO "${base}/gitleaks_${GITLEAKS_VERSION}_checksums.txt"
grep " gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz$" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" | sha256sum -c -
tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" gitleaks && install -m 0755 gitleaks "$BIN/gitleaks"
echo "::endgroup::"

trivy --version | head -1
gitleaks version
