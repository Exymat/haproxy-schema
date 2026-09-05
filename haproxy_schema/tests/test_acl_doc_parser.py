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
    assert "compatible with IP address samples only" in acl.match_methods["ip"]
    assert not acl.match_methods["ip"].endswith("It is compatible")
    assert "eq" in acl.int_operators
    assert "str" in acl.string_match_methods
    assert "sub" in acl.string_match_methods
    assert "HTTP" in acl.predefined_acls

    assert "binary or string samples" in acl.match_methods["dom"]
    assert "jsess_present" not in acl.match_methods["dom"]
    assert "Input sample type" not in acl.match_methods["dom"]
    assert "valid-ua" not in acl.flags["--"]
    assert "extracted string" in acl.string_match_methods["beg"]
    assert "looked up inside" in acl.string_match_methods["sub"]


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
                "   -- : force end of flags. Useful when a string looks like one of the flags.",
                "",
                "The -f flag is followed by a file name.",
                "",
                "    acl valid-ua hdr(user-agent) -f exact-ua.lst -i -f generic-ua.lst test",
                "",
                "The pattern matching method must be one of the following :",
                "",
                '   - "found" : only check if the requested sample could be found.',
                '   - "ip"    : match the value as an IPv4 or IPv6 address. It is compatible',
                "              with IP address samples only, so it is implied and never needed.",
                '   - "dom"   : domain match : check that a dot-delimited portion of the contents',
                "              exactly match one of the provided string patterns. This may be",
                "              used with binary or string samples.",
                "",
                "For example, to quickly detect a cookie:",
                "",
                "    acl jsess_present req.cook(JSESSIONID) -m found",
                "",
                "                           +-------------------------------------------------+",
                "                           |                Input sample type                |",
                "",
                "7.1.1. Next section",
                "-------------------",
                "",
                "7.1.3. Matching strings",
                "-----------------------",
                "",
                "  - prefix match    (-m beg) : the patterns are compared with the beginning of",
                "    the extracted string, and the ACL matches if any of them matches.",
                "",
                "  - substring match (-m sub) : the patterns are looked up inside the",
                "    extracted string, and the ACL matches if any of them is found inside;",
                "",
                "7.1.4. Matching regular expressions",
                "-----------------------------------",
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
    assert acl.flags["--"] == (
        "force end of flags. Useful when a string looks like one of the flags."
    )
    assert "valid-ua" not in acl.flags["--"]
    assert acl.match_methods["ip"] == (
        "match the value as an IPv4 or IPv6 address. It is compatible "
        "with IP address samples only, so it is implied and never needed."
    )
    assert acl.match_methods["dom"] == (
        "domain match : check that a dot-delimited portion of the contents "
        "exactly match one of the provided string patterns. This may be "
        "used with binary or string samples."
    )
    assert "jsess_present" not in acl.match_methods["dom"]
    assert "Input sample type" not in acl.match_methods["dom"]
    assert acl.string_match_methods["beg"] == (
        "the patterns are compared with the beginning of "
        "the extracted string, and the ACL matches if any of them matches."
    )
    assert "looked up inside" in acl.string_match_methods["sub"]
