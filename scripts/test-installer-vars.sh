#!/bin/sh
set -eu

if grep -nE '(^|[^[:alnum:]_])VERSION=' install.sh || grep -nE '\$\{VERSION\}|\$VERSION([^[:alnum:]_]|$)' install.sh; then
  echo "install.sh must not use VERSION because /etc/os-release defines it" >&2
  exit 1
fi

grep -Eq '^RELEASE_VERSION=[0-9]+\.[0-9]+\.[0-9]+$' install.sh || {
  echo "install.sh must define a semantic RELEASE_VERSION" >&2
  exit 1
}
