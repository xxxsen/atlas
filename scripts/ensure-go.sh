#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${ATLAS_GO_VERSION:-1.26.9}"
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
  1.26.9-linux-amd64) expected="42d158b4d8f7b61ac0a830567c940a86098fb7aac52e467a5ebec03ef5cc2f8d" ;;
  1.26.9-linux-arm64) expected="4a97373d49fcacdcf3694fea368a500b00ee3e963974f3e7514132717632f052" ;;
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
