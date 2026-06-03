from haproxy_schema.acl_doc_parser import parse_acl_reference

from ._paths import haproxy_configuration_txt


def test_parse_acl_reference_from_configuration_txt() -> None:
    path = haproxy_configuration_txt("3.2")
    if not path.is_file():
        return

    acl = parse_acl_reference(path)

    assert "-i" in acl.flags
    assert "-m" in acl.flags
    assert "--" in acl.flags
    assert "int" in acl.match_methods
    assert "found" in acl.match_methods
    assert "eq" in acl.int_operators
    assert "str" in acl.string_match_methods
    assert "sub" in acl.string_match_methods
    assert "HTTP" in acl.predefined_acls
