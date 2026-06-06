from __future__ import annotations

import pytest

from haproxy_schema.config_validator import validate_config
from haproxy_schema.schema import HaproxySchema

from ._paths import haproxy_vscode_root

SCHEMA_PATH = haproxy_vscode_root() / "schemas" / "haproxy-3.2.schema.json"


@pytest.fixture(scope="module")
def schema() -> HaproxySchema:
    if not SCHEMA_PATH.is_file():
        pytest.skip(f"schema not built: {SCHEMA_PATH}")
    return HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("name", "config"),
    [
        (
            "macros_are_ignored",
            """\
frontend fe_main
  .if defined(HAPROXY_MWORKER)
  .notice "SSL support is mandatory"
  .endif
  bind :80
  mode http
""",
        ),
        (
            "no_prefix_keywords_are_accepted",
            """\
frontend fe_main
  bind :80
  no log
""",
        ),
        (
            "option_and_no_option_lines_are_accepted",
            """\
defaults
  option httplog
  no option dontlognull
""",
        ),
        (
            "prefix_families_resolve_subcommands",
            """\
defaults
  timeout connect 5s
frontend fe_main
  bind :80
  tcp-request inspect-delay 5s
  stats enable
""",
        ),
        (
            "multi_token_directive_is_accepted",
            """\
frontend fe_main
  bind :80
  http-request set-header X-Test value
""",
        ),
        (
            "unknown_newer_section_is_tolerated_to_prevent_false_positives",
            """\
defaults
  timeout connect 5s
log-profile keylog-fc
  on any format "${HAPROXY_KEYLOG_FC_LOG_FMT}"
""",
        ),
    ],
)
def test_valid_patterns_have_no_unknown_keyword_issues(
    schema: HaproxySchema,
    name: str,
    config: str,
) -> None:
    del name
    result = validate_config(config, schema)
    assert result.unknown_keyword_issues == []


def test_unknown_directive_is_reported(schema: HaproxySchema) -> None:
    content = """\
frontend fe_main
  bind :80
  this-directive-does-not-exist foo
"""
    unknown = validate_config(content, schema).unknown_keyword_issues
    assert len(unknown) == 1
    assert unknown[0].keyword.startswith("this-directive-does-not-exist")


def test_unknown_prefix_subcommand_is_reported(schema: HaproxySchema) -> None:
    content = """\
frontend fe_main
  bind :80
  tcp-request not-a-phase value
"""
    unknown = validate_config(content, schema).unknown_keyword_issues
    assert len(unknown) == 1
    assert unknown[0].keyword == "tcp-request not-a-phase value"
