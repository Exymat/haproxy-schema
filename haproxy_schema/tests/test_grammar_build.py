from __future__ import annotations

import json
import re
import tempfile
from copy import deepcopy
from pathlib import Path

from haproxy_schema.grammar_build import build_tm_language, validate_line_isolated_grammar
from haproxy_schema.grammar_emitter import write_tm_language
from haproxy_schema.grammar_util import collect_directive_keywords
from haproxy_schema.schema import HaproxySchema, Keyword, Section

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


def test_multword_filter_directives_generated() -> None:
    schema = HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))
    if "filter cache" not in schema.keywords:
        return
    grammar = build_tm_language(schema)
    multi = grammar["repository"]["directives-multiword"]["patterns"]
    filter_rules = [p for p in multi if r"\b(filter)\s+" in p.get("match", "")]
    assert filter_rules, "expected filter multi-word rules"
    match = filter_rules[0]["match"]
    assert "cache" in match


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


def test_directives_include_hyphen_prefix_keywords() -> None:
    schema = HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))
    directives = collect_directive_keywords(schema)
    assert "h1-case-adjust" in directives
    assert "h1-case-adjust-file" in directives
    assert "log-format-sd" in directives or "log_format_sd" in directives
    assert "log" in directives


def test_boundary_alt_rejects_hyphenated_prefix_matches() -> None:
    schema = HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))
    grammar = build_tm_language(schema)
    schema_match = grammar["repository"]["schema-directives"]["patterns"][0]["match"]
    assert "(?!-)" in schema_match
    assert re.search(schema_match, "h1-case-adjust from to")
    assert re.search(schema_match, "h1-case-adjust-file /tmp/headers")
    assert re.search(schema_match, "log-format %ci:%cp").group(0) == "log-format"

    cache_match = grammar["repository"]["cache-keywords"]["patterns"][0]["match"]
    assert "(?!-)" in cache_match

    rule_actions = grammar["repository"]["rule-actions"]["patterns"]
    http_request_rule = next(
        p for p in rule_actions if r"\b(http\-request)\s+" in p.get("match", "")
    )
    assert r"cache\-use" in http_request_rule["match"]


def test_distinct_name_scopes_for_theme_highlighting() -> None:
    schema = HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))
    grammar = build_tm_language(schema)
    sections = grammar["repository"]["sections"]["patterns"]
    defaults_rule = next(p for p in sections if "(defaults)" in p.get("match", ""))
    proxy_rule = next(p for p in sections if "frontend" in p.get("match", ""))
    label_scope = "entity.name.type.class.proxy.haproxy"
    assert defaults_rule["captures"]["2"]["name"] == label_scope
    assert proxy_rule["captures"]["2"]["name"] == label_scope

    directives = grammar["repository"]["directives-with-values"]["patterns"]
    acl_rule = next(p for p in directives if r"\b(acl)\s+" in p.get("match", ""))
    assert acl_rule["captures"]["2"]["name"] == "entity.other.attribute-name.acl.haproxy"
    assert acl_rule["captures"]["2"]["name"] != label_scope


def test_process_vary_on_scoped_as_boolean_value() -> None:
    schema = HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))
    grammar = build_tm_language(schema)
    directives = grammar["repository"]["directives-with-values"]["patterns"]
    process_vary_rules = [
        p
        for p in directives
        if "process\\-vary" in p.get("match", "")
        and p.get("captures", {}).get("2", {}).get("name") == "constant.language.boolean.haproxy"
    ]
    assert process_vary_rules, "expected process-vary on/off rule with boolean capture"


def test_condition_and_boolean_scopes_are_explicit() -> None:
    schema = HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))
    grammar = build_tm_language(schema)

    condition_patterns = grammar["repository"]["condition-keywords"]["patterns"]
    boolean_patterns = grammar["repository"]["boolean-literals"]["patterns"]

    assert condition_patterns[0]["name"] == "keyword.control.conditional.haproxy"
    assert r"\b(?:if|unless)\b" == condition_patterns[0]["match"]
    assert boolean_patterns[0]["name"] == "constant.language.boolean.haproxy"
    assert "enabled" in boolean_patterns[0]["match"]
    assert "disabled" in boolean_patterns[0]["match"]


def test_acl_flag_and_comparison_scopes_are_explicit() -> None:
    schema = HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))
    grammar = build_tm_language(schema)

    acl_flag_patterns = grammar["repository"]["acl-flags"]["patterns"]
    comparison_patterns = grammar["repository"]["comparison-operators"]["patterns"]

    assert acl_flag_patterns[0]["name"] == "storage.modifier.acl.haproxy"
    assert comparison_patterns[0]["name"] == "keyword.operator.comparison.haproxy"
    assert "eq" in comparison_patterns[0]["match"]
    assert "ge" in comparison_patterns[0]["match"]


def test_written_grammar_uses_local_schema_sidecar() -> None:
    schema = HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp_dir:
        grammar_path = Path(tmp_dir) / "haproxy.tmLanguage.json"

        write_tm_language(schema, grammar_path)

        grammar = json.loads(grammar_path.read_text(encoding="utf-8"))
        sidecar = Path(tmp_dir) / "tmlanguage.schema.json"
        sidecar_json = json.loads(sidecar.read_text(encoding="utf-8"))

        assert grammar["$schema"] == "./tmlanguage.schema.json"
        assert sidecar.is_file()
        assert sidecar_json["title"] == "TextMate Grammar"


def test_schema_directive_pattern_is_stable_for_equal_length_keywords() -> None:
    schema_a = HaproxySchema(version="test")
    for name in ("bind", "server", "alpha", "bravo", "delta", "charlie"):
        schema_a.keywords[name] = Keyword(name=name)
    schema_a.sections["defaults"] = Section(
        name="defaults",
        keywords=["bind", "server", "alpha", "bravo", "delta", "charlie"],
    )

    schema_b = deepcopy(schema_a)
    schema_b.keywords = {name: schema_b.keywords[name] for name in reversed(list(schema_b.keywords.keys()))}
    schema_b.sections["defaults"].keywords = list(reversed(schema_b.sections["defaults"].keywords))

    grammar_a = build_tm_language(schema_a)
    grammar_b = build_tm_language(schema_b)

    assert grammar_a["repository"]["schema-directives"]["patterns"][0]["match"] == (
        grammar_b["repository"]["schema-directives"]["patterns"][0]["match"]
    )


def test_generated_grammar_is_line_isolated() -> None:
    schema = HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))
    grammar = build_tm_language(schema)
    validate_line_isolated_grammar(grammar)
