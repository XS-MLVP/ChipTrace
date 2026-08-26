#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export PYTHONPATH="$repo_root/src${PYTHONPATH:+:$PYTHONPATH}"

python3 -m unittest discover -s tests -v
node --test tests/js/*.test.js
python3 -m trace_pipeline self-test
python3 scripts/benchmark.py --records 500 --payload-bytes 4096 --workers 16
