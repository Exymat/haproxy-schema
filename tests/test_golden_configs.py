from __future__ import annotations

from pathlib import Path

import pytest

from haproxy_schema.config_validator import validate_config_file
from haproxy_schema.schema import HaproxySchema

from ._paths import haproxy_vscode_root, monorepo_root

_MONO = monorepo_root()
SCHEMA_PATH = haproxy_vscode_root() / "schemas" / "haproxy-3.2.schema.json"
CONF_DIRS = (
    [_MONO / "haproxy_git" / "haproxy-3.2" / "tests" / "conf"] if _MONO is not None else []
)


@pytest.fixture(scope="module")
def schema() -> HaproxySchema:
    if not SCHEMA_PATH.is_file():
        pytest.skip(f"schema not built: {SCHEMA_PATH}")
    return HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))


def _collect_cfg_files() -> list[Path]:
    files: list[Path] = []
    for root in CONF_DIRS:
        if not root.is_dir():
            continue
        files.extend(sorted(root.rglob("*.cfg")))
    return files


@pytest.mark.parametrize("cfg_path", _collect_cfg_files(), ids=lambda p: p.name)
def test_valid_config_has_no_unknown_keyword(schema: HaproxySchema, cfg_path: Path) -> None:
    result = validate_config_file(cfg_path, schema)
    unknown = result.unknown_keyword_issues
    if unknown:
        sample = "\n".join(f"  L{i.line + 1}: {i.message}" for i in unknown[:5])
        pytest.fail(f"{cfg_path.name}: {len(unknown)} unknown-keyword issue(s)\n{sample}")
