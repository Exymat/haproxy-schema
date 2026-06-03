from haproxy_schema.config_validator import validate_config
from haproxy_schema.schema import HaproxySchema

from ._paths import haproxy_vscode_root


def test_no_log_is_valid_when_log_is_invertible() -> None:
    schema_path = haproxy_vscode_root() / "schemas" / "haproxy-3.2.schema.json"
    if not schema_path.is_file():
        return

    schema = HaproxySchema.from_json(schema_path.read_text(encoding="utf-8"))
    if "log" not in schema.tokens.get("no_prefix_keywords", []):
        return

    content = """frontend test
  bind :80
  no log
"""
    result = validate_config(content, schema)
    assert result.unknown_keyword_issues == []
