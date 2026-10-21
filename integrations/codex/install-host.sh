#!/bin/sh
# Install the native Stock Codex integration atomically.
#
# Usage:
#   sudo ./install-host.sh /path/to/chiptrace-ingest-token

set -eu
umask 077

if [ "$(id -u)" -ne 0 ]; then
  echo "install-host: run as root (for example: sudo $0 TOKEN_FILE)" >&2
  exit 1
fi

token_source=${1:-}
if [ -z "$token_source" ] || [ ! -r "$token_source" ] || [ ! -s "$token_source" ]; then
  echo "install-host: readable, non-empty token file is required" >&2
  exit 2
fi

source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
codex_dir=${CHIPTRACE_CODEX_ETC_DIR:-/etc/codex}
libexec_dir=${CHIPTRACE_CODEX_LIBEXEC_DIR:-/usr/local/libexec}
token_dir=${CHIPTRACE_CODEX_TOKEN_DIR:-/etc/chiptrace}
backup_dir=${CHIPTRACE_CODEX_BACKUP_DIR:-/var/lib/chiptrace-codex/backups}

if [ ! -d "$codex_dir" ]; then
  echo "install-host: missing Codex system directory: $codex_dir" >&2
  exit 1
fi

codex_group=${CHIPTRACE_CODEX_GROUP:-$(stat -c '%G' "$codex_dir" 2>/dev/null || true)}
if [ -z "$codex_group" ] || [ "$codex_group" = "root" ] || [ "$codex_group" = "UNKNOWN" ]; then
  echo "install-host: set CHIPTRACE_CODEX_GROUP to the group that runs Codex" >&2
  exit 1
fi

getent group "$codex_group" >/dev/null 2>&1 || {
  echo "install-host: unknown Codex group: $codex_group" >&2
  exit 1
}

stamp=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$backup_dir"
chmod 0700 "$backup_dir"
chown root:root "$backup_dir"
backup_file() {
  source=$1
  name=$2
  if [ -f "$source" ]; then
    backup_path="$backup_dir/$name.before-chiptrace-$stamp"
    cp -p "$source" "$backup_path"
    # A previous requirements file, helper, or token may contain a credential.
    # Keep rollback evidence root-only even when the active source is
    # group-readable by Codex.
    chmod 0600 "$backup_path"
    chown root:root "$backup_path"
  fi
}
backup_file "$codex_dir/config.toml" config.toml
backup_file "$codex_dir/requirements.toml" requirements.toml
backup_file "$libexec_dir/chiptrace-codex-hook" chiptrace-codex-hook
backup_file "$token_dir/ingest-token" ingest-token

install -d -m 0755 -o root -g root "$libexec_dir"
install -d -m 0750 -o root -g "$codex_group" "$token_dir"

install_atomic() {
  source=$1
  destination=$2
  mode=$3
  owner=$4
  group=$5
  temporary="$destination.tmp.$$"
  trap 'rm -f "$temporary"' 0 1 2 3 15
  install -m "$mode" -o "$owner" -g "$group" "$source" "$temporary"
  mv -f "$temporary" "$destination"
  trap - 0 1 2 3 15
}

install_atomic "$source_dir/config.toml.example" \
  "$codex_dir/config.toml" 0640 root "$codex_group"
install_atomic "$source_dir/requirements.toml.example" \
  "$codex_dir/requirements.toml" 0640 root "$codex_group"
install_atomic "$source_dir/chiptrace-codex-hook.sh" \
  "$libexec_dir/chiptrace-codex-hook" 0755 root root
install_atomic "$token_source" \
  "$token_dir/ingest-token" 0640 root "$codex_group"

if grep -Eq 'configuration incomplete|172\.28\.11\.121|CHIPTRACE_INGEST_TOKEN[[:space:]]*=' \
  "$codex_dir/requirements.toml"; then
  echo "install-host: installed requirements still contains a legacy marker" >&2
  exit 1
fi

cmp -s "$source_dir/requirements.toml.example" "$codex_dir/requirements.toml"
cmp -s "$source_dir/chiptrace-codex-hook.sh" "$libexec_dir/chiptrace-codex-hook"
test -s "$token_dir/ingest-token"

echo "install-host: installed Stock Codex Trace integration"
echo "install-host: requirements=$codex_dir/requirements.toml"
echo "install-host: helper=$libexec_dir/chiptrace-codex-hook"
echo "install-host: token=$token_dir/ingest-token (0640 root:$codex_group)"
echo "install-host: backups=$backup_dir/*before-chiptrace-$stamp"
# A managed app-server reads the required provider and Hooks once at startup.
# Installing new requirements does not reconfigure daemons that are already
# running; turn/start replies -32600 until those daemons are refreshed.
echo "install-host: running Codex app-server daemons keep their startup requirements;"
echo "install-host: refresh each user's daemon when idle: codex app-server daemon update --from-cli -y"
