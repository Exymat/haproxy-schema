from __future__ import annotations

import pytest

from haproxy_schema.doc_audit import build_doc_audit_report

from ._paths import dkall_dump, haproxy_configuration_txt


def test_build_doc_audit_report_smoke() -> None:
    doc_path = haproxy_configuration_txt("3.2")
    dkall_path = dkall_dump("3.2")
    if not doc_path.is_file() or not dkall_path.is_file():
        pytest.skip("missing HAProxy sources")

    report = build_doc_audit_report("3.2", doc_path, dkall_path)
    payload = report.to_dict()
    assert payload["version"] == "3.2"
    assert isinstance(payload["proxy_options_missing"], list)
    assert isinstance(payload["bind_options_missing"], list)
    assert isinstance(payload["server_options_missing"], list)
