from haproxy_schema.action_parser import ActionDoc
from haproxy_schema.language_data import action_docs_url, build_language_data
from haproxy_schema.tests._paths import dkall_dump, haproxy_configuration_txt
from haproxy_schema.doc_parser import parse_configuration
from haproxy_schema.dkall_parser import parse_dkall


def test_action_docs_url_uses_explicit_dconv_keyword_for_legacy_actions() -> None:
    action = ActionDoc(
        name="allow",
        signature="http-request allow",
        docs_keyword="http-request allow",
        chapter="4.2",
    )
    assert action_docs_url("2.6", action, "allow", "4.4") == (
        "https://docs.haproxy.org/2.6/configuration.html#4.2-http-request%20allow"
    )


def test_language_data_legacy_action_links_follow_inline_42_anchors() -> None:
    version = "2.6"
    doc_path = haproxy_configuration_txt(version)
    if not doc_path.is_file():
        return

    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_dump(version))
    language = build_language_data(version, doc, dkall, doc.action_reference)

    allow = next(item for item in language.groups["http_request_actions"] if item.name == "allow")
    assert allow.docsUrl.endswith("#4.2-http-request%20allow")
