from pathlib import Path

from haproxy_schema.dkall_parser import parse_dkall
from haproxy_schema.doc_parser import parse_configuration
from haproxy_schema.merge import build_action_groups

from ._paths import dkall_dump, haproxy_configuration_txt


def test_build_action_groups_merges_doc_matrix_with_dkall() -> None:
    doc_path = haproxy_configuration_txt("3.2")
    dkall_path = dkall_dump("3.2")
    if not doc_path.is_file() or not dkall_path.is_file():
        return

    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    groups = build_action_groups(doc, dkall)

    assert "set-var" in groups["http_request_actions"]
    assert "track-sc0" in groups["http_request_actions"]
    assert "track-sc" in groups["http_request_actions"]
    assert "ot-group" in groups["http_request_actions"]
