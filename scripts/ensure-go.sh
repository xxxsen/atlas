#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${ATLAS_GO_VERSION:-1.26.10}"
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
  1.26.10-linux-amd64) expected="ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5" ;;
  1.26.10-linux-arm64) expected="3f4227ce7b206a513e794f1393adb473a07b46e94d18bd15d1c684bbb7319797" ;;
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
