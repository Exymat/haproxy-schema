from __future__ import annotations

from pathlib import Path

import pytest

from haproxy_schema.config_validator import validate_config_file
from haproxy_schema.schema import HaproxySchema

from ._paths import hapee_root, haproxy_vscode_root, monorepo_root

_MONO = monorepo_root()
VERSIONS = ("2.6", "2.8", "3.0", "3.2", "3.4")
_HAPEE_ONLY_GLOBAL_KEYWORDS = {"module-load", "module-path", "saml-sso-load"}


def _schema_path(version: str) -> Path:
    return haproxy_vscode_root() / "schemas" / f"haproxy-{version}.schema.json"


def _conf_dirs(version: str) -> list[Path]:
    files: list[Path] = []
    if _MONO is not None:
        upstream = _MONO / "haproxy_git" / f"haproxy-{version}" / "tests" / "conf"
        if upstream.is_dir():
            files.extend(sorted(upstream.rglob("*.cfg")))
    if version == "3.2":
        hapee = hapee_root()
        if hapee is not None:
            files.extend(sorted(p for p in hapee.glob("*/haproxy.cfg") if p.is_file()))
    return files


def _cfg_test_id(path: Path) -> str:
    if path.name == "haproxy.cfg" and path.parent.name != "conf":
        return f"{path.parent.name}/haproxy.cfg"
    return path.name


def _is_expected_hapee_only_keyword(path: Path, keyword: str) -> bool:
    hapee = hapee_root()
    return (
        hapee is not None
        and path.is_relative_to(hapee)
        and keyword.split(maxsplit=1)[0].lower() in _HAPEE_ONLY_GLOBAL_KEYWORDS
    )


@pytest.mark.parametrize("version", VERSIONS)
def test_valid_config_has_no_unknown_keyword(version: str) -> None:
    schema_path = _schema_path(version)
    if not schema_path.is_file():
        pytest.skip(f"schema not built: {schema_path}")
    cfg_files = _conf_dirs(version)
    if not cfg_files:
        pytest.skip(f"no conf corpus available for {version}")

    schema = HaproxySchema.from_json(schema_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    for cfg_path in cfg_files:
        result = validate_config_file(cfg_path, schema)
        unknown = [
            issue
            for issue in result.unknown_keyword_issues
            if not _is_expected_hapee_only_keyword(cfg_path, issue.keyword)
        ]
        if not unknown:
            continue
        sample = "\n".join(f"    L{i.line + 1}: {i.message}" for i in unknown[:3])
        failures.append(
            f"- {_cfg_test_id(cfg_path)}: {len(unknown)} unknown-keyword issue(s)\n{sample}"
        )
    if failures:
        pytest.fail(f"{version}: {len(failures)} config(s) with unknown-keyword\n" + "\n".join(failures[:15]))
