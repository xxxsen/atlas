#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${ATLAS_GO_VERSION:-1.26.6}"
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
  1.26.6-linux-amd64) expected="708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89" ;;
  1.26.6-linux-arm64) expected="d0507e9e9d7fe012aae570108cbd76c15de879e17130ab8cb90d4d7445cb1f2e" ;;
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
