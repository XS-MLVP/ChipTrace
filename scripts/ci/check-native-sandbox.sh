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
# Actually enter the namespace and prove the shared root is read-only. The
# released producer creates a private daemon socket below /tmp even when the
# requested tools use a read-only sandbox, so exercise that mount here too.
# No host file is written and no permission setting is changed here.
private_tmp=$(mktemp -d "${TMPDIR:-/tmp}/chiptrace-bwrap.XXXXXX")
probe_name="chiptrace-bwrap-probe-${BASHPID}"
probe_file="$private_tmp/$probe_name"
trap 'rm -rf -- "$private_tmp"' EXIT
bwrap --unshare-user --unshare-pid --die-with-parent \
  --ro-bind / / --proc /proc --dev /dev --bind "$private_tmp" /tmp \
  --setenv CHIPTRACE_BWRAP_PROBE_NAME "$probe_name" -- \
  /bin/sh -ceu 'test -r /etc/os-release && test ! -w /etc && test -w /tmp
    probe="/tmp/$CHIPTRACE_BWRAP_PROBE_NAME"
    printf "private daemon socket probe\n" > "$probe"
    test -s "$probe"
    printf "BWRAP_READ_ONLY_OK\n"'
test -s "$probe_file"
printf '%s\n' 'BWRAP_PRIVATE_TMP_OK'
