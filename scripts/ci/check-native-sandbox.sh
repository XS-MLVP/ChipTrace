#!/usr/bin/env bash
set -euo pipefail

if ! command -v bwrap >/dev/null; then
  printf '%s\n' 'native producer sandbox requires system bubblewrap (bwrap) on PATH' >&2
  exit 127
fi
bwrap --version
trace_bwrap_help=$(bwrap --help)
if ! [[ "$trace_bwrap_help" == *--perms* ]]; then
  printf '%s\n' 'native producer sandbox requires Bubblewrap --perms support' >&2
  exit 1
fi
unshare --user --map-root-user /bin/true
# Actually enter the namespace and prove the shared root is read-only.
# No host file is written and no permission setting is changed here.
bwrap --unshare-user --unshare-pid --die-with-parent \
  --ro-bind / / --proc /proc --dev /dev -- \
  /bin/sh -c 'test -r /etc/os-release && test ! -w /etc && printf "BWRAP_READ_ONLY_OK\n"'
