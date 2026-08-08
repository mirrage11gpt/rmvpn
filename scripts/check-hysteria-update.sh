#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 <upstream-tag>" >&2; exit 2; }
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/risevpn-hysteria-update.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM

git clone --depth 1 --branch "$1" https://github.com/apernet/hysteria.git "$WORK/source"
for patch in "$ROOT"/hysteria-patches/*.patch; do
  git -C "$WORK/source" apply --check "$patch"
  git -C "$WORK/source" apply "$patch"
done
echo "Patch series applies cleanly to $1"
