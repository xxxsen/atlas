#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${ATLAS_GO_VERSION:-1.26.5}"
TARGET="$ROOT/.cache/go-runtime"
GO_BIN="$TARGET/bin/go"

if [[ -x "$GO_BIN" ]] && [[ "$(GOTOOLCHAIN=local "$GO_BIN" version)" == "go version go${VERSION} "* ]]; then
  exit 0
fi

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
  x86_64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [[ "$os" != "linux" ]]; then
  echo "automatic Go installation currently supports Linux only; override GO=/path/to/go" >&2
  exit 1
fi

case "${VERSION}-${os}-${arch}" in
  1.26.5-linux-amd64) expected="5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053" ;;
  1.26.5-linux-arm64) expected="fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49" ;;
  *) echo "no pinned checksum for Go ${VERSION} ${os}/${arch}" >&2; exit 1 ;;
esac

archive="go${VERSION}.${os}-${arch}.tar.gz"
url="https://go.dev/dl/$archive"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

echo "[atlas] downloading Go ${VERSION} for ${os}/${arch}"
curl -fL --retry 3 --output "$tmp_dir/$archive" "$url"
actual="$(sha256sum "$tmp_dir/$archive" | awk '{print $1}')"
if [[ "$actual" != "$expected" ]]; then
  echo "Go archive checksum mismatch: expected $expected, got $actual" >&2
  exit 1
fi

mkdir -p "$ROOT/.cache"
rm -rf "$TARGET" "$tmp_dir/go"
tar -C "$tmp_dir" -xzf "$tmp_dir/$archive"
mv "$tmp_dir/go" "$TARGET"
echo "[atlas] installed $(GOTOOLCHAIN=local "$GO_BIN" version)"
