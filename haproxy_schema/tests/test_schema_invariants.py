from __future__ import annotations

import json
from pathlib import Path

import pytest

from haproxy_schema.line_layout import prefix_subcommands

PACKAGE_DIR = Path(__file__).resolve().parents[1]
VERSIONS = ("2.6", "2.8", "3.0", "3.2", "3.4")


@pytest.fixture(params=VERSIONS)
def schema_dict(request: pytest.FixtureRequest) -> dict:
    path = PACKAGE_DIR.parent / ".." / "haproxy-vscode" / "schemas" / f"haproxy-{request.param}.schema.json"
    if not path.exists():
        pytest.skip(f"missing schema artifact: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def test_schema_has_line_layout(schema_dict: dict) -> None:
    layout = schema_dict.get("line_layout")
    assert layout, "line_layout must be present"
    assert layout.get("prefix_families")
    assert layout.get("stats_socket_levels") == ["admin", "operator", "user"]


def test_schema_excludes_hapee_only_module_keywords(schema_dict: dict) -> None:
    keywords = schema_dict["keywords"]
    global_keywords = schema_dict["sections"]["global"]["keywords"]
    assert "module-load" not in keywords
    assert "module-path" not in keywords
    assert "module-load" not in global_keywords
    assert "module-path" not in global_keywords


def test_tcp_phases_match_keywords(schema_dict: dict) -> None:
    layout = schema_dict["line_layout"]
    keywords = list(schema_dict["keywords"].keys())
    assert layout["tcp_request_phases"] == prefix_subcommands(keywords, "tcp-request")
    assert layout["tcp_response_phases"] == prefix_subcommands(keywords, "tcp-response")


def test_options_with_value_is_subset(schema_dict: dict) -> None:
    options = schema_dict["keyword_groups"].get("options", [])
    with_value = schema_dict["keyword_groups"].get("options_with_value", [])
    assert set(with_value).issubset(set(options))
    bind_options = schema_dict["keyword_groups"].get("bind_options", [])
    bind_with_value = schema_dict["keyword_groups"].get("bind_options_with_value", [])
    assert set(bind_with_value).issubset(set(bind_options))
    server_options = schema_dict["keyword_groups"].get("server_options", [])
    server_with_value = schema_dict["keyword_groups"].get("server_options_with_value", [])
    assert set(server_with_value).issubset(set(server_options))


def test_bind_and_server_slots_have_address_policy(schema_dict: dict) -> None:
    for rule in schema_dict.get("statement_rules", []):
        if rule.get("keyword") not in {"bind", "server"}:
            continue
        slots = rule.get("fixed_slots") or []
        address_slots = [slot for slot in slots if slot.get("role") == "address"]
        assert address_slots, f"{rule['keyword']} should define address slots"
        assert all(slot.get("address_policy") for slot in address_slots)


def test_statement_rules_have_semantic_match_metadata(schema_dict: dict) -> None:
    for rule in schema_dict.get("statement_rules", []):
        assert rule.get("match_tokens"), f"statement rule missing match_tokens: {rule.get('keyword')}"
        assert "minimum_token_index" in rule, (
            f"statement rule missing minimum_token_index: {rule.get('keyword')}"
        )


def test_schema_has_reference_patterns(schema_dict: dict) -> None:
    patterns = schema_dict.get("reference_patterns", [])
    assert patterns
    assert any(pattern.get("reference_kind") == "resolvers" for pattern in patterns)


def test_schema_kind_sets_are_stable_across_versions() -> None:
    reference_path = PACKAGE_DIR.parent / ".." / "haproxy-vscode" / "schemas" / "haproxy-3.2.schema.json"
    reference = json.loads(reference_path.read_text(encoding="utf-8"))
    reference_rule_kinds = sorted({rule["kind"] for rule in reference.get("statement_rules", [])})
    reference_action_kinds = sorted(
        reference.get("semantic_groups", {}).get("completion_kind_to_action_group", {}).keys()
    )
    for version in VERSIONS:
        path = PACKAGE_DIR.parent / ".." / "haproxy-vscode" / "schemas" / f"haproxy-{version}.schema.json"
        if not path.exists():
            continue
        schema = json.loads(path.read_text(encoding="utf-8"))
        rule_kinds = sorted({rule["kind"] for rule in schema.get("statement_rules", [])})
        action_kinds = sorted(
            schema.get("semantic_groups", {}).get("completion_kind_to_action_group", {}).keys()
        )
        assert rule_kinds == reference_rule_kinds, version
        assert action_kinds == reference_action_kinds, version


def test_schema_has_source_metadata_payloads(schema_dict: dict) -> None:
    assert schema_dict.get("address_policies", {}).get("bind") == {
        "portMandatory": True,
        "portOffset": False,
        "portOk": True,
        "portRange": True,
    }
    sample_types = schema_dict.get("sample_types")
    assert sample_types[0] == "any"
    assert {"bool", "sint", "addr", "ipv4", "ipv6", "str", "bin", "meth"}.issubset(
        set(sample_types)
    )
    assert len(schema_dict.get("sample_casts", [])) == len(schema_dict["sample_types"])
    assert schema_dict.get("symbols", {}).get("proxy_sections") == [
        "frontend",
        "backend",
        "listen",
    ]
    assert "completion_kind_to_action_group" in schema_dict.get("semantic_groups", {})
    assert schema_dict.get("semantic_groups", {}).get("acl_ref_groups") == [
        "acl_flags",
        "acl_match_methods",
        "acl_int_operators",
        "acl_string_match_methods",
        "acl_predefined",
    ]
    assert "logformat_stop_tokens" in schema_dict.get("validation_rules", {})
