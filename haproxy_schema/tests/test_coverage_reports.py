from __future__ import annotations

import json
from pathlib import Path

import pytest

from haproxy_schema.coverage import build_coverage_report
from haproxy_schema.dkall_parser import parse_dkall
from haproxy_schema.doc_parser import parse_configuration
from haproxy_schema.merge import merge_schema

from ._paths import dkall_dump, haproxy_configuration_txt, schema_repo_root

VERSIONS = ("2.6", "2.8", "3.0", "3.2", "3.4")
_MAX_DOC_ONLY_DELTA = 5
_MAX_WITHOUT_MODEL_DELTA = 3


def _expected_coverage_path(version: str) -> Path:
    return schema_repo_root() / "haproxy_schema" / f"coverage-{version}.json"


@pytest.mark.parametrize("version", VERSIONS)
def test_coverage_reports_do_not_drift_unexpectedly(version: str) -> None:
    expected_path = _expected_coverage_path(version)
    doc_path = haproxy_configuration_txt(version)
    dkall_path = dkall_dump(version)

    if not expected_path.is_file():
        pytest.skip(f"missing expected coverage artifact: {expected_path}")
    if not doc_path.is_file():
        pytest.skip(f"missing HAProxy doc source: {doc_path}")
    if not dkall_path.is_file():
        pytest.skip(f"missing dkall source: {dkall_path}")

    expected = json.loads(expected_path.read_text(encoding="utf-8"))

    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    schema = merge_schema(version, doc, dkall, dkall_package_dir=dkall_path.parent)
    actual = build_coverage_report(version, doc, dkall, schema).to_dict()

    assert set(actual["dkall_only_keywords"]) == set(expected["dkall_only_keywords"])
    assert len(actual["doc_only_keywords"]) <= len(expected["doc_only_keywords"]) + _MAX_DOC_ONLY_DELTA
    assert len(actual["keywords_without_argument_model"]) <= (
        len(expected["keywords_without_argument_model"]) + _MAX_WITHOUT_MODEL_DELTA
    )
    assert set(actual["sections_dkall_only"]) == set(expected["sections_dkall_only"])
