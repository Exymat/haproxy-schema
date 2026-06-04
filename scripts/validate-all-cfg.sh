#!/usr/bin/env bash
# Validate all upstream tests/conf and examples/*.cfg against version-matched schemas.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MONOREPO_ROOT="$(cd "${TOOLS_ROOT}/.." && pwd)"
export PYTHONPATH="${TOOLS_ROOT}"
export MONOREPO_ROOT

python3 - <<'PY'
from pathlib import Path
import os
import sys

from haproxy_schema.config_validator import validate_config_file
from haproxy_schema.schema import HaproxySchema

parent = Path(os.environ["MONOREPO_ROOT"]).resolve()

vscode = parent / "haproxy-vscode"
git = parent / "haproxy_git"
versions = ["3.0", "3.2", "3.4"]
failed: list[tuple[str, str, str, int, str]] = []
total = 0

for ver in versions:
    schema_path = vscode / "schemas" / f"haproxy-{ver}.schema.json"
    if not schema_path.is_file():
        print(f"error: missing {schema_path}", file=sys.stderr)
        sys.exit(1)
    schema = HaproxySchema.from_json(schema_path.read_text(encoding="utf-8"))
    for sub in ("tests/conf", "examples"):
        root = git / f"haproxy-{ver}" / sub
        if not root.is_dir():
            print(f"skip: {root} (not found)")
            continue
        cfgs = sorted(root.rglob("*.cfg"))
        print(f"\n== {ver} {sub}: {len(cfgs)} files ==")
        for cfg in cfgs:
            total += 1
            result = validate_config_file(cfg, schema)
            unknown = result.unknown_keyword_issues
            if unknown:
                failed.append((ver, sub, cfg.name, len(unknown), unknown[0].message))
                print(f"  FAIL {cfg.name}: {len(unknown)} unknown-keyword")

if failed:
    print(f"\n{len(failed)}/{total} failure(s):", file=sys.stderr)
    for item in failed[:30]:
        print(" ", item, file=sys.stderr)
    sys.exit(1)
print(f"\nAll {total} cfg files passed unknown-keyword validation (3.0, 3.2, 3.4)")
PY
