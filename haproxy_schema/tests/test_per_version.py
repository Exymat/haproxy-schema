"""Integration tests that must pass for every supported HAProxy version."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from haproxy_schema.coverage import build_coverage_report
from haproxy_schema.doc_layout import detect_doc_layout
from haproxy_schema.doc_parser import parse_configuration
from haproxy_schema.dkall_parser import parse_dkall
from haproxy_schema.language_data import build_language_data
from haproxy_schema.line_layout import prefix_subcommands
from haproxy_schema.merge import merge_schema
from haproxy_schema.schema import HaproxySchema

from ._paths import (
    LEGACY_DOC_VERSIONS,
    MODERN_DOC_VERSIONS,
    SUPPORTED_VERSIONS,
    dkall_dump,
    haproxy_configuration_txt,
    haproxy_vscode_root,
    schema_repo_root,
)


def _require_sources(version: str) -> tuple[Path, Path]:
    doc_path = haproxy_configuration_txt(version)
    dkall_path = dkall_dump(version)
    if not doc_path.is_file():
        pytest.skip(f"missing HAProxy doc source: {doc_path}")
    if not dkall_path.is_file():
        pytest.skip(f"missing dkall source: {dkall_path}")
    return doc_path, dkall_path


def _load_built_schema(version: str) -> dict:
    schema_path = haproxy_vscode_root() / "schemas" / f"haproxy-{version}.schema.json"
    if not schema_path.is_file():
        pytest.skip(f"schema not built: {schema_path}")
    return json.loads(schema_path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_parse_configuration(version: str) -> None:
    doc_path, _ = _require_sources(version)
    result = parse_configuration(doc_path)
    assert result.keyword_docs
    assert result.signatures
    assert result.matrix_keywords
    assert result.proxy_keywords


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_doc_layout_matches_release(version: str) -> None:
    doc_path, _ = _require_sources(version)
    lines = doc_path.read_text(encoding="utf-8", errors="replace").splitlines()
    layout = detect_doc_layout(lines)
    if version in LEGACY_DOC_VERSIONS:
        assert layout.actions == "legacy"
        assert layout.standalone == "chapter3"
    elif version in MODERN_DOC_VERSIONS:
        assert layout.actions == "modern"
        if version in {"3.2", "3.4"}:
            assert layout.standalone == "chapter12"
        else:
            assert layout.standalone == "chapter3"


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_merge_schema(version: str) -> None:
    doc_path, dkall_path = _require_sources(version)
    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    schema = merge_schema(version, doc, dkall, dkall_package_dir=dkall_path.parent)
    assert schema.version == version
    assert schema.keywords
    assert schema.sections
    assert schema.statement_rules
    assert schema.keyword_groups.get("http_request_actions")
    assert schema.keyword_groups.get("bind_options") is not None
    assert schema.line_layout.get("prefix_families")


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_build_language_data(version: str) -> None:
    doc_path, dkall_path = _require_sources(version)
    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    actions = doc.action_reference or {}
    language = build_language_data(version, doc, dkall, actions)
    assert language.version == version
    assert language.keywords
    assert language.groups.get("http_request_actions")
    assert language.groups.get("options") is not None


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_coverage_report(version: str) -> None:
    doc_path, dkall_path = _require_sources(version)
    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    schema = merge_schema(version, doc, dkall, dkall_package_dir=dkall_path.parent)
    report = build_coverage_report(version, doc, dkall, schema)
    payload = report.to_dict()
    assert payload["version"] == version
    assert isinstance(payload["doc_only_keywords"], list)
    assert isinstance(payload["dkall_only_keywords"], list)


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_built_schema_has_core_invariants(version: str) -> None:
    doc_path, dkall_path = _require_sources(version)
    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    schema = merge_schema(version, doc, dkall, dkall_package_dir=dkall_path.parent)

    kinds = {rule.kind for rule in schema.statement_rules}
    assert "option" in kinds
    assert "bind" in kinds
    assert "http-request" in kinds

    by_keyword = {rule.keyword: rule for rule in schema.statement_rules}
    assert by_keyword["use_backend"].reference_kind == "proxy-section"
    assert by_keyword["use_backend"].match_tokens == ["use_backend"]
    assert by_keyword["use_backend"].minimum_token_index == 1
    assert by_keyword["server"].definition_kind == "server"
    assert by_keyword["server"].match_tokens == ["server"]
    assert by_keyword["server"].minimum_token_index == 3
    assert len(schema.sample_fetches) > 20
    assert len(schema.sample_converters) > 10
    assert any(pattern.reference_kind == "resolvers" for pattern in schema.reference_patterns)

    layout = schema.line_layout
    keywords = list(schema.keywords.keys())
    assert layout["stats_socket_levels"] == ["admin", "operator", "user"]
    assert layout["tcp_request_phases"] == prefix_subcommands(keywords, "tcp-request")
    assert layout["tcp_response_phases"] == prefix_subcommands(keywords, "tcp-response")


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_checked_in_schema_artifact_invariants(version: str) -> None:
    schema_dict = _load_built_schema(version)
    layout = schema_dict.get("line_layout")
    assert layout and layout.get("prefix_families")
    options = schema_dict["keyword_groups"].get("options", [])
    with_value = schema_dict["keyword_groups"].get("options_with_value", [])
    assert set(with_value).issubset(set(options))
    assert schema_dict.get("reference_patterns")


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_audit_snapshot_artifacts_exist(version: str) -> None:
    root = schema_repo_root() / "haproxy_schema"
    for name in (f"doc-parse-audit-{version}.json", f"schema-fidelity-audit-{version}.json"):
        path = root / name
        assert path.is_file(), f"missing audit snapshot: {path}"
        json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_legacy_action_reference_when_expected(version: str) -> None:
    doc_path, _ = _require_sources(version)
    doc = parse_configuration(doc_path)
    if version in LEGACY_DOC_VERSIONS:
        assert doc.action_reference
        assert doc.action_matrix.get("http_request_actions")
        assert len(doc.action_matrix["http_request_actions"]) >= 20
    else:
        assert doc.action_reference
        assert "accept" in doc.action_reference or "deny" in doc.action_reference


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_schema_roundtrip(version: str) -> None:
    doc_path, dkall_path = _require_sources(version)
    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    schema = merge_schema(version, doc, dkall, dkall_package_dir=dkall_path.parent)
    restored = HaproxySchema.from_json_dict(json.loads(schema.to_json()))
    assert restored.version == version
    assert restored.keywords.keys() == schema.keywords.keys()
