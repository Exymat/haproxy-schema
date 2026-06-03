from __future__ import annotations

from pathlib import Path

import pytest

from haproxy_schema.grammar_coverage import build_grammar_coverage_report, report_from_paths
from haproxy_schema.grammar_emitter import emit_tm_language
from haproxy_schema.grammar_util import collect_directive_keywords
from haproxy_schema.schema import HaproxySchema

ROOT = Path(__file__).resolve().parents[2]
VSCODE_ROOT = ROOT.parent / "haproxy-vscode"
SCHEMA_PATH = VSCODE_ROOT / "schemas" / "haproxy-3.2.schema.json"
TEMPLATE_PATH = VSCODE_ROOT / "syntaxes" / "haproxy.tmLanguage.json"


@pytest.fixture(scope="module")
def schema() -> HaproxySchema:
    return HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_generated_grammar_has_no_legacy_directives_single() -> None:
    grammar = emit_tm_language(
        HaproxySchema.from_json(SCHEMA_PATH.read_text(encoding="utf-8"))
    )
    assert "directives-single" not in grammar.get("repository", {})


def test_use_backend_in_schema_and_directive_list(schema: HaproxySchema) -> None:
    assert "use_backend" in schema.keywords
    directives = collect_directive_keywords(schema)
    assert "use_backend" in directives
    assert "log" not in directives
    assert "process" not in directives


def test_emitted_grammar_covers_all_schema_directives(schema: HaproxySchema) -> None:
    grammar = emit_tm_language(schema)
    report = build_grammar_coverage_report(schema, grammar)
    assert report.missing_in_grammar == [], report.missing_in_grammar
    assert report.missing_cache_in_grammar == [], report.missing_cache_in_grammar
    assert report.prefix_conflicts_in_grammar == [], report.prefix_conflicts_in_grammar


def test_use_backend_in_generated_grammar(schema: HaproxySchema) -> None:
    grammar = emit_tm_language(schema)
    repo = grammar["repository"]["schema-directives"]["patterns"][0]["match"]
    assert "use_backend" in repo


@pytest.mark.skipif(not SCHEMA_PATH.is_file(), reason="schema not built")
def test_report_from_paths() -> None:
    report = report_from_paths(SCHEMA_PATH, SCHEMA_PATH, template_path=TEMPLATE_PATH)
    assert report.ok
