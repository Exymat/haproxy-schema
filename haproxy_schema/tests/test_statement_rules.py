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
    assert len(schema.sample_fetches) > 50
    assert len(schema.sample_converters) > 20
    assert "resolvers" in schema.sections or "crt-store" in schema.sections
