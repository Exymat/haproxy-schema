from pathlib import Path

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


def test_parse_acl_reference_preserves_case_sensitive_flag_names() -> None:
    path = Path(__file__).with_name("_tmp_acl_reference_configuration.txt")
    path.write_text(
        "\n".join(
            [
                "7.1. ACL matching booleans",
                "----------------------",
                "",
                "The following ACL flags are currently supported :",
                "",
                "   -m : use a specific pattern matching method",
                "   -M : load the file pointed by -f like a map.",
                "",
                "The pattern matching method must be one of the following :",
                "",
                '   - "found" : only check if the requested sample could be found.',
                "",
                "7.1.1. Next section",
                "-------------------",
            ]
        ),
        encoding="utf-8",
    )
    try:
        acl = parse_acl_reference(path)
    finally:
        path.unlink(missing_ok=True)

    assert acl.flags["-m"] == "use a specific pattern matching method"
    assert acl.flags["-M"] == "load the file pointed by -f like a map."
