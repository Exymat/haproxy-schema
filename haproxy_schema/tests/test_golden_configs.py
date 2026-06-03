from __future__ import annotations

from pathlib import Path

import pytest

from haproxy_schema.config_validator import validate_config_file
from haproxy_schema.schema import HaproxySchema

from ._paths import hapee_root, haproxy_vscode_root, monorepo_root

_MONO = monorepo_root()
SCHEMA_PATH = haproxy_vscode_root() / "schemas" / "haproxy-3.2.schema.json"


def _conf_dirs() -> list[Path]:
    roots: list[Path] = []
    if _MONO is not None:
        upstream = _MONO / "haproxy_git" / "haproxy-3.2" / "tests" / "conf"
        if upstream.is_dir():
            roots.append(upstream)
    hapee = hapee_root()
    if hapee is not None:
        roots.extend(sorted(p.parent for p in hapee.glob("*/haproxy.cfg")))
    return roots


CONF_DIRS = _conf_dirs()


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
        hapee_cfg = root / "haproxy.cfg"
        if hapee_cfg.is_file():
            files.append(hapee_cfg)
            continue
        files.extend(sorted(root.rglob("*.cfg")))
    return files


def _cfg_test_id(path: Path) -> str:
    if path.name == "haproxy.cfg" and path.parent.name != "conf":
        return f"{path.parent.name}/haproxy.cfg"
    return path.name


@pytest.mark.parametrize("cfg_path", _collect_cfg_files(), ids=_cfg_test_id)
def test_valid_config_has_no_unknown_keyword(schema: HaproxySchema, cfg_path: Path) -> None:
    result = validate_config_file(cfg_path, schema)
    unknown = result.unknown_keyword_issues
    if unknown:
        sample = "\n".join(f"  L{i.line + 1}: {i.message}" for i in unknown[:5])
        pytest.fail(f"{cfg_path.name}: {len(unknown)} unknown-keyword issue(s)\n{sample}")
