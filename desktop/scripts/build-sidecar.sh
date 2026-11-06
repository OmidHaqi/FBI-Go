#!/bin/sh
set -eu

target=$(rustc --print host-tuple)
case "$target" in
  x86_64-unknown-linux-gnu) goarch=amd64 ;;
  aarch64-unknown-linux-gnu) goarch=arm64 ;;
  *) echo "Unsupported Linux target: $target" >&2; exit 1 ;;
esac

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$repo/desktop/src-tauri/binaries"
cd "$repo"
release_version=${FBI_GO_RELEASE_VERSION:-$(node -p "require('./desktop/package.json').version")}
case "$release_version" in *[!a-zA-Z0-9.+-]*|'') echo "Invalid release version" >&2; exit 1 ;; esac
CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -ldflags="-s -w -X main.version=$release_version" -o "desktop/src-tauri/binaries/fbi-$target" ./cmd/fbi
