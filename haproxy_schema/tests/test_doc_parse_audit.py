from __future__ import annotations

import json
from pathlib import Path

import pytest

from haproxy_schema.doc_parse_audit import build_doc_parse_audit_report

from ._paths import dkall_dump, haproxy_configuration_txt, schema_repo_root

VERSIONS = ("2.6", "2.8", "3.0", "3.2", "3.4")


def _expected_audit_path(version: str) -> Path:
    return schema_repo_root() / "haproxy_schema" / f"doc-parse-audit-{version}.json"


@pytest.mark.parametrize("version", VERSIONS)
def test_doc_parse_audit_snapshot(version: str) -> None:
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
    actual = build_doc_parse_audit_report(version, doc_path, dkall_path).to_dict()

    assert actual == expected


def test_doc_parse_audit_smoke() -> None:
    doc_path = haproxy_configuration_txt("3.2")
    dkall_path = dkall_dump("3.2")
    if not doc_path.is_file() or not dkall_path.is_file():
        pytest.skip("missing 3.2 sources")

    report = build_doc_parse_audit_report("3.2", doc_path, dkall_path)
    assert report.keyword_docs_count > 0
    assert report.signature_keywords_count > 0
    assert report.language_keywords_count > 0
