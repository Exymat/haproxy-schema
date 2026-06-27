from __future__ import annotations

import json
from pathlib import Path

import pytest

from haproxy_schema.schema_fidelity_audit import build_schema_fidelity_report

from ._paths import dkall_dump, haproxy_configuration_txt, schema_repo_root

VERSIONS = ("2.6", "2.8", "3.0", "3.2", "3.4")


def _expected_audit_path(version: str) -> Path:
    return schema_repo_root() / "haproxy_schema" / f"schema-fidelity-audit-{version}.json"


@pytest.mark.parametrize("version", VERSIONS)
def test_schema_fidelity_audit_snapshot(version: str) -> None:
    expected_path = _expected_audit_path(version)
    doc_path = haproxy_configuration_txt(version)
    dkall_path = dkall_dump(version)

    if not expected_path.is_file():
        pytest.skip(f"missing expected audit artifact: {expected_path}")
    if not doc_path.is_file():
        pytest.skip(f"missing HAProxy doc source: {doc_path}")
    if not dkall_path.is_file():
        pytest.skip(f"missing dkall source: {dkall_path}")

    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    actual = build_schema_fidelity_report(version, doc_path, dkall_path).to_dict()

    assert actual == expected


def test_schema_fidelity_audit_smoke() -> None:
    doc_path = haproxy_configuration_txt("3.4")
    dkall_path = dkall_dump("3.4")
    if not doc_path.is_file() or not dkall_path.is_file():
        pytest.skip("missing 3.4 sources")

    report = build_schema_fidelity_report("3.4", doc_path, dkall_path)
    assert report.keywords_with_signatures_count > 0
    assert report.keywords_with_argument_model_count > 0
    assert report.sample_fetches.structured_count > 0
    assert any(item.keyword == "server" for item in report.keywords)
    assert any(item.group == "server_options" for item in report.group_items)
    assert report.line_option_semantic_gaps == []
    assert report.statement_rule_semantic_gaps == []
    assert report.reference_pattern_gaps == []
