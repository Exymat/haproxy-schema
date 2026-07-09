from __future__ import annotations

from pathlib import Path

import pytest

from haproxy_schema.grammar_coverage import build_grammar_coverage_report, report_from_paths
from haproxy_schema.grammar_emitter import emit_tm_language
from haproxy_schema.grammar_util import collect_directive_keywords
from haproxy_schema.schema import HaproxySchema

ROOT = Path(__file__).resolve().parents[2]
VSCODE_ROOT = ROOT.parent / "haproxy-vscode"
VERSIONS = ("2.6", "2.8", "3.0", "3.2", "3.4")


def _schema_path(version: str) -> Path:
    return VSCODE_ROOT / "schemas" / f"haproxy-{version}.schema.json"


@pytest.fixture(params=VERSIONS)
def schema(request: pytest.FixtureRequest) -> HaproxySchema:
    schema_path = _schema_path(request.param)
    if not schema_path.is_file():
        pytest.skip(f"schema not built: {schema_path}")
    return HaproxySchema.from_json(schema_path.read_text(encoding="utf-8"))


def test_generated_grammar_has_no_legacy_directives_single() -> None:
    schema_path = _schema_path("3.2")
    if not schema_path.is_file():
        pytest.skip(f"schema not built: {schema_path}")
    grammar = emit_tm_language(
        HaproxySchema.from_json(schema_path.read_text(encoding="utf-8"))
    )
    assert "directives-single" not in grammar.get("repository", {})


def test_use_backend_in_schema_and_directive_list(schema: HaproxySchema) -> None:
    assert "use_backend" in schema.keywords
    directives = collect_directive_keywords(schema)
    assert "use_backend" in directives
    assert "log" in directives
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


@pytest.mark.parametrize("version", VERSIONS)
def test_report_from_paths(version: str) -> None:
    schema_path = _schema_path(version)
    if not schema_path.is_file():
        pytest.skip(f"schema not built: {schema_path}")
    report = report_from_paths(schema_path, schema_path)
    assert report.ok
