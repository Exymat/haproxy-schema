from __future__ import annotations

from pathlib import Path

from haproxy_schema.grammar_build import build_tm_language
from haproxy_schema.grammar_util import collect_directive_keywords
from haproxy_schema.schema import HaproxySchema

SCHEMA_PATH = Path(__file__).resolve().parents[2].parent / "haproxy-vscode" / "schemas" / "haproxy-3.2.schema.json"


def test_multword_timeout_generated() -> None:
    schema = HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))
    grammar = build_tm_language(schema)
    multi = grammar["repository"]["directives-multiword"]["patterns"]
    timeout_rules = [p for p in multi if r"\b(timeout)\s+" in p.get("match", "")]
    assert timeout_rules, "expected timeout multi-word rules"
    match = timeout_rules[0]["match"]
    assert "client" in match or r"client\-fin" in match
    assert "http-keep-alive" in match or r"http\-keep\-alive" in match


def test_rule_actions_include_http_after_response() -> None:
    schema = HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))
    grammar = build_tm_language(schema)
    rules = grammar["repository"]["rule-actions"]["patterns"]
    combined = " ".join(p.get("match", "") for p in rules)
    assert "http-after-response" in combined or r"http\-after\-response" in combined
    assert "set-header" in combined or r"set\-header" in combined


def test_bind_options_from_schema() -> None:
    schema = HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))
    grammar = build_tm_language(schema)
    bind = grammar["repository"]["bind-param-pairs"]["patterns"]
    combined = " ".join(p.get("match", "") + (p.get("name", "") or "") for p in bind)
    assert "name" in combined
    assert "process(?!-)" in combined or "process" in combined


def test_directives_exclude_log_prefix_ambiguity() -> None:
    schema = HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))
    directives = collect_directive_keywords(schema)
    assert "log-format-sd" in directives or "log_format_sd" in directives
    assert "log" not in directives
