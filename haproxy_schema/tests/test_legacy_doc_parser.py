from pathlib import Path

from haproxy_schema.doc_layout import detect_doc_layout
from haproxy_schema.doc_parser import parse_configuration
from haproxy_schema.legacy_action_parser import parse_legacy_proxy_actions
from haproxy_schema.tests._paths import haproxy_configuration_txt


def test_detect_legacy_layout_for_26() -> None:
    path = haproxy_configuration_txt("2.6")
    if not path.is_file():
        return
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    layout = detect_doc_layout(lines)
    assert layout.actions == "legacy"
    assert layout.standalone == "chapter3"


def test_detect_modern_layout_for_32() -> None:
    path = haproxy_configuration_txt("3.2")
    if not path.is_file():
        return
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    layout = detect_doc_layout(lines)
    assert layout.actions == "modern"
    assert layout.standalone == "chapter12"


def test_legacy_26_extracts_http_request_actions() -> None:
    path = haproxy_configuration_txt("2.6")
    if not path.is_file():
        return
    result = parse_configuration(path)
    actions = result.action_matrix["http_request_actions"]
    assert "allow" in actions
    assert "deny" in actions
    assert "set-header" in actions
    assert "redirect" in actions
    assert len(actions) >= 40


def test_legacy_26_userlist_section_keywords() -> None:
    path = haproxy_configuration_txt("2.6")
    if not path.is_file():
        return
    result = parse_configuration(path)
    userlist = result.section_keywords.get("userlist", set())
    assert "group" in userlist
    assert "user" in userlist


def test_legacy_26_proxy_keywords_exclude_action_docs() -> None:
    path = haproxy_configuration_txt("2.6")
    if not path.is_file():
        return
    result = parse_configuration(path)
    assert "http-request" in result.proxy_keywords
    assert "http-request set-header" not in result.proxy_keywords


def test_modern_32_unchanged_action_count() -> None:
    path = haproxy_configuration_txt("3.2")
    if not path.is_file():
        return
    result = parse_configuration(path)
    assert len(result.action_matrix["http_request_actions"]) >= 60


def test_legacy_supported_block_parsing() -> None:
    lines = [
        "4.2. Alphabetically sorted keywords reference",
        "---------------------------------------------",
        "",
        "http-request <action> [options...]",
        "  Description.",
        "",
        "  supported:",
        "    - allow",
        "    - deny [ { status | deny_status } <code>]  ...",
        "    - set-header <name> <fmt>",
        "",
        "http-request allow [ { if | unless } <condition> ]",
        "  Allow description.",
        "",
        "5. Bind and server options",
        "--------------------------",
    ]
    _, matrix = parse_legacy_proxy_actions(lines, 0, len(lines))
    assert matrix["http_request_actions"] == {"allow", "deny", "set-header"}
