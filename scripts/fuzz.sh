#!/usr/bin/env bash
# Runs every fuzz target in the root module for FUZZTIME each (default 15s).
set -euo pipefail
cd "$(dirname "$0")/.."

fuzztime=${FUZZTIME:-15s}
targets=$(go test -run '^$' -list '^Fuzz' ./... | awk '
  /^Fuzz/ { names[n++] = $1; next }
  /^ok/   { for (i = 0; i < n; i++) print $2, names[i]; n = 0 }')

if [ -z "$targets" ]; then
  echo "no fuzz targets found" >&2
  exit 1
fi

echo "$targets" | while read -r pkg name; do
  echo "== $pkg $name"
  go test "$pkg" -run '^$' -fuzz "^${name}\$" -fuzztime "$fuzztime"
done
