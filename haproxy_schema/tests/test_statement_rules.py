from haproxy_schema.dkall_parser import parse_dkall
from haproxy_schema.doc_parser import parse_configuration
from haproxy_schema.merge import merge_schema

from ._paths import dkall_dump, haproxy_configuration_txt


def test_schema_contains_statement_rules_and_samples() -> None:
    doc = parse_configuration(haproxy_configuration_txt("3.2"))
    dkall = parse_dkall(dkall_dump("3.2"))
    schema = merge_schema("3.2", doc, dkall)

    kinds = {rule.kind for rule in schema.statement_rules}
    assert "option" in kinds
    assert "bind" in kinds
    assert "http-request" in kinds

    by_keyword = {rule.keyword: rule for rule in schema.statement_rules}
    assert by_keyword["use_backend"].reference_kind == "proxy-section"
    assert by_keyword["use_backend"].match_tokens == ["use_backend"]
    assert by_keyword["use_backend"].minimum_token_index == 1
    assert by_keyword["use-server"].reference_kind == "server"
    assert by_keyword["server"].definition_kind == "server"
    assert by_keyword["server"].match_tokens == ["server"]
    assert by_keyword["server"].minimum_token_index == 3
    assert by_keyword["acl"].definition_kind == "acl"
    assert by_keyword["filter"].definition_kind == "filter"
    assert any(pattern.reference_kind == "resolvers" for pattern in schema.reference_patterns)
    assert len(schema.sample_fetches) > 50
    assert len(schema.sample_converters) > 20
    assert "resolvers" in schema.sections or "crt-store" in schema.sections
