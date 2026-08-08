#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TAG=$(sed -n '1p' "$ROOT/hysteria-patches/UPSTREAM_VERSION")
WORK=$(mktemp -d "${TMPDIR:-/tmp}/risevpn-hysteria.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM

git clone --depth 1 --branch "$TAG" https://github.com/apernet/hysteria.git "$WORK/source"
for patch in "$ROOT"/hysteria-patches/*.patch; do
  git -C "$WORK/source" apply --check "$patch"
  git -C "$WORK/source" apply "$patch"
done

mkdir -p "$ROOT/target"
(cd "$WORK/source/core" && go test ./server)
(cd "$WORK/source/app" && go build -trimpath -ldflags "-s -w -X github.com/apernet/hysteria/app/v2/cmd.appVersion=risevpn-$TAG" -o "$ROOT/target/hysteria-risevpn" .)
echo "$ROOT/target/hysteria-risevpn"
