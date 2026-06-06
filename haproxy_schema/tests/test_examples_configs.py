"""Upstream HAProxy example configs must not produce unknown-keyword diagnostics."""

from __future__ import annotations

from pathlib import Path

import pytest

from haproxy_schema.config_validator import validate_config_file
from haproxy_schema.schema import HaproxySchema

from ._paths import haproxy_vscode_root

VERSIONS = ("2.6", "2.8", "3.0", "3.2", "3.4")


def _schema_path(version: str) -> Path:
    return haproxy_vscode_root() / "schemas" / f"haproxy-{version}.schema.json"


def _examples_dir(version: str) -> Path:
    return haproxy_vscode_root().parent / "haproxy_git" / f"haproxy-{version}" / "examples"


@pytest.mark.parametrize("version", VERSIONS)
def test_example_cfg_has_no_unknown_keywords(version: str) -> None:
    schema_path = _schema_path(version)
    if not schema_path.is_file():
        pytest.skip(f"schema not built: {schema_path}")

    examples_dir = _examples_dir(version)
    if not examples_dir.is_dir():
        pytest.skip(f"examples directory not available: {examples_dir}")
    cfg_files = sorted(examples_dir.glob("*.cfg"))
    if not cfg_files:
        pytest.skip(f"no example cfg files for {version}")

    schema = HaproxySchema.from_json(schema_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    for cfg_path in cfg_files:
        unknown = validate_config_file(cfg_path, schema).unknown_keyword_issues
        if not unknown:
            continue
        sample = "\n".join(f"    L{i.line + 1}: {i.message}" for i in unknown[:3])
        failures.append(f"- {cfg_path.name}: {len(unknown)} unknown-keyword issue(s)\n{sample}")
    if failures:
        pytest.fail(f"{version}: {len(failures)} example config(s) with unknown-keyword\n" + "\n".join(failures[:15]))
