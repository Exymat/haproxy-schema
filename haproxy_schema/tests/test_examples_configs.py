"""Upstream HAProxy example configs must not produce unknown-keyword diagnostics."""

from __future__ import annotations

from pathlib import Path

import pytest

from haproxy_schema.config_validator import validate_config_file
from haproxy_schema.schema import HaproxySchema

from ._paths import haproxy_vscode_root

SCHEMA_PATH = haproxy_vscode_root() / "schemas" / "haproxy-3.2.schema.json"
EXAMPLES_DIR = haproxy_vscode_root().parent / "haproxy_git" / "haproxy-3.2" / "examples"


@pytest.fixture(scope="module")
def schema() -> HaproxySchema:
    if not SCHEMA_PATH.is_file():
        pytest.skip(f"schema not built: {SCHEMA_PATH}")
    return HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))


def _example_cfg_files() -> list[Path]:
    if not EXAMPLES_DIR.is_dir():
        return []
    return sorted(EXAMPLES_DIR.glob("*.cfg"))


@pytest.mark.parametrize("cfg_path", _example_cfg_files(), ids=lambda p: p.name)
def test_example_cfg_has_no_unknown_keywords(schema: HaproxySchema, cfg_path: Path) -> None:
    if not cfg_path.is_file():
        pytest.skip("examples directory not available")
    result = validate_config_file(cfg_path, schema)
    unknown = result.unknown_keyword_issues
    if unknown:
        sample = "\n".join(f"  L{i.line}: {i.message}" for i in unknown[:5])
        pytest.fail(f"{cfg_path.name}: {len(unknown)} unknown-keyword issue(s)\n{sample}")
