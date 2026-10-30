#!/usr/bin/env bash
# Install the pinned ChipTrace Codex producer as a complete Codex package.
#
# A patched Codex is only usable when it is a package: Codex resolves its
# command runner (codex-code-mode-host), ripgrep and bubblewrap from the layout
# around the binary. A lone binary still chats, but every exec tool fails to
# spawn and thread search breaks -- silently, until a session needs them.
# Installing through this script makes that class of failure impossible.
set -euo pipefail

CANONICAL_ROOT="${CODEX_CANONICAL_INSTALL_ROOT:-/nfs/home/zhangyuxin/.local/openai-codex}"
PACKAGE_VERSION="${CODEX_PATCHED_VERSION:-0.163.0-alpha.11}"
PACKAGE_ROOT="${CODEX_PATCHED_ROOT:-$CANONICAL_ROOT/patched/$PACKAGE_VERSION-chiptrace}"
PRODUCER_ROOT="${CHIPTRACE_PRODUCER_ROOT:-/nfs/home/zhangyuxin/router_v2/codex-producer-0.163.0}"
SMOKE_TIMEOUT="${CODEX_PATCHED_SMOKE_TIMEOUT:-180}"

usage() {
  cat <<'EOF'
Usage: install-patched-codex.sh [options]

  --binary <path>   install this prebuilt patched CLI (default: the producer
                    tree's release build)
  --build           build the producer tree first, then install it
  --verify          check the installed package and exit; installs nothing
  --root <dir>      package root (default: $CODEX_CANONICAL_INSTALL_ROOT/patched/<version>-chiptrace)

Environment:
  CODEX_PATCHED_SKIP_SMOKE=1   skip the end-to-end tool-execution check

The patched CLI is installed as bin/codex; codex-code-mode-host, rg and bwrap
are taken from the newest official release package of the same version, because
the producer patches touch app-server/core/login only and never those helpers.
EOF
}

binary=""
build=0
verify_only=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary) binary="${2:-}"; shift 2 ;;
    --build) build=1; shift ;;
    --verify) verify_only=1; shift ;;
    --root) PACKAGE_ROOT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'ERROR: unsupported argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '%s\n' "$*"; }

official_package() {
  local candidate
  for candidate in "$CANONICAL_ROOT"/releases/"$PACKAGE_VERSION"-*/node_modules/@openai/codex-linux-*/vendor/*/bin/codex; do
    [ -x "$candidate" ] || continue
    dirname "$(dirname "$candidate")"
    return 0
  done
  return 1
}

# Prints the missing parts; empty output means the package is complete.
missing_parts() {
  local root="$1" missing=""
  [ -f "$root/codex-package.json" ] || missing="$missing codex-package.json"
  [ -x "$root/bin/codex" ] || missing="$missing bin/codex"
  [ -x "$root/bin/codex-code-mode-host" ] || missing="$missing bin/codex-code-mode-host"
  [ -x "$root/codex-path/rg" ] || missing="$missing codex-path/rg"
  [ -x "$root/codex-resources/bwrap" ] || missing="$missing codex-resources/bwrap"
  printf '%s' "$missing"
}

# The real proof is an end-to-end run: file presence alone would have passed the
# install that broke every tool call. It runs through the launcher into a
# throwaway node home, so it exercises the same auth/config plumbing real
# sessions use without leaving a probe session in the shared inventory.
smoke_test() {
  local root="$1" work rc=0 launcher
  if [ "${CODEX_PATCHED_SKIP_SMOKE:-0}" = "1" ]; then
    log "smoke test skipped (CODEX_PATCHED_SKIP_SMOKE=1)"
    return 0
  fi
  work="$(mktemp -d)"
  # Pre-create sessions/ so the launcher does not symlink the shared session
  # store in: the probe must not show up in real session pickers.
  mkdir -p "$work/home" "$work/ws" "$work/home/sessions"
  launcher="$(command -v codex || true)"
  if [ -n "$launcher" ]; then
    if ! ( cd "$work/ws" && CODEX_PATCHED_ROOT="$root" CODEX_NODE_HOME="$work/home" \
        timeout "$SMOKE_TIMEOUT" "$launcher" exec --skip-git-repo-check --sandbox read-only \
        "run 'echo codex-tools-ok' and report the exact output" >"$work/out" 2>&1 ); then
      rc=1
    fi
  elif ! ( cd "$work/ws" && CODEX_HOME="$work/home" timeout "$SMOKE_TIMEOUT" \
      "$root/bin/codex" exec --skip-git-repo-check --sandbox read-only \
      "run 'echo codex-tools-ok' and report the exact output" >"$work/out" 2>&1 ); then
    rc=1
  fi
  grep -q "succeeded in" "$work/out" || rc=1
  grep -q "codex-tools-ok" "$work/out" || rc=1
  if [ "$rc" -ne 0 ]; then
    tail -20 "$work/out" >&2
    rm -rf "$work"
    fail "smoke test failed: the patched CLI could not execute a command"
  fi
  rm -rf "$work"
  log "smoke test passed: the patched CLI executes commands"
}

if [ "$verify_only" = "1" ]; then
  missing="$(missing_parts "$PACKAGE_ROOT")"
  [ -z "$missing" ] || fail "incomplete patched package $PACKAGE_ROOT:$missing"
  log "package ok: $PACKAGE_ROOT"
  exit 0
fi

if [ "$build" = "1" ] && [ -z "$binary" ]; then
  log "building producer (release, codex + codex-code-mode-host)..."
  ( cd "$PRODUCER_ROOT/src/codex-rs" \
    && RUSTUP_TOOLCHAIN=1.95.0-x86_64-unknown-linux-gnu cargo build --release \
         -p codex-cli --bin codex -p codex-code-mode-host --bin codex-code-mode-host --locked )
fi

if [ -z "$binary" ]; then
  binary="$PRODUCER_ROOT/src/codex-rs/target/release/codex"
  [ -x "$binary" ] || fail "no release build at $binary; pass --binary <path> or --build"
fi
[ -x "$binary" ] || fail "not executable: $binary"

official="$(official_package)" || fail "no official $PACKAGE_VERSION release package under $CANONICAL_ROOT/releases"

staging="$PACKAGE_ROOT.staging.$$"
previous="$PACKAGE_ROOT.previous.$$"
rollback() {
  rm -rf "$staging"
  if [ -d "$previous" ] && [ ! -e "$PACKAGE_ROOT" ]; then
    mv "$previous" "$PACKAGE_ROOT"
  fi
}
trap rollback EXIT

mkdir -p "$staging/bin" "$staging/codex-path" "$staging/codex-resources"
install -m 0755 "$binary" "$staging/bin/codex"
install -m 0755 "$official/bin/codex-code-mode-host" "$staging/bin/codex-code-mode-host"
install -m 0755 "$official/codex-path/rg" "$staging/codex-path/rg"
install -m 0755 "$official/codex-resources/bwrap" "$staging/codex-resources/bwrap"
if [ -d "$official/codex-resources/voice" ]; then
  cp -R "$official/codex-resources/voice" "$staging/codex-resources/voice"
fi

target="${official#*/vendor/}"
target="${target%%/*}"
python3 - "$staging/codex-package.json" "$PACKAGE_VERSION" "$target" <<'PY'
import json, sys
path, version, target = sys.argv[1:4]
with open(path, "w", encoding="utf-8") as handle:
    json.dump({
        "layoutVersion": 1,
        "version": version,
        "target": target or "x86_64-unknown-linux-gnu",
        "variant": "codex",
        "entrypoint": "bin/codex",
        "resourcesDir": "codex-resources",
        "pathDir": "codex-path",
    }, handle, indent=2)
    handle.write("\n")
PY

missing="$(missing_parts "$staging")"
[ -z "$missing" ] || fail "staged package is incomplete:$missing"

smoke_test "$staging"

if [ -e "$PACKAGE_ROOT" ]; then
  mv "$PACKAGE_ROOT" "$previous"
fi
mv "$staging" "$PACKAGE_ROOT"
missing="$(missing_parts "$PACKAGE_ROOT")"
if [ -n "$missing" ]; then
  rm -rf "$PACKAGE_ROOT"
  [ -d "$previous" ] && mv "$previous" "$PACKAGE_ROOT"
  fail "installed package is incomplete:$missing; previous install restored"
fi
rm -rf "$previous"
trap - EXIT

log "installed patched Codex package: $PACKAGE_ROOT"
log "launcher picks it up through CODEX_PATCHED_ROOT; re-check any time with: $0 --verify"
