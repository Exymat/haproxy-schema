from __future__ import annotations

from haproxy_schema.dkall_parser import DkallParseResult
from haproxy_schema.doc_parser import DocParseResult
from haproxy_schema.enterprise_overlays import (
    apply_enterprise_module_overlays,
    enterprise_module_docs_url,
)


def test_response_body_filter_is_available_in_all_supported_hapee_releases() -> None:
    doc = DocParseResult()
    dkall = DkallParseResult()
    apply_enterprise_module_overlays("2.6r1", doc, dkall)
    assert {"htmldom", "waf"} <= dkall.filters
    assert "waf-body-limit" in doc.section_keywords["global"]
    assert "udp-lb" not in doc.section_keywords
    assert "botmgmt-profile" not in doc.section_keywords


def test_udp_module_adds_its_section_and_versioned_directives() -> None:
    doc = DocParseResult()
    dkall = DkallParseResult()
    apply_enterprise_module_overlays("3.2r1", doc, dkall)
    assert {"dgram-bind", "proxy-requests", "accepted-payload-size", "hash-type"} <= doc.section_keywords[
        "udp-lb"
    ]
    assert "option udp-check" in doc.section_keywords["udp-lb"]


def test_oidc_module_adds_section_global_and_actions_only_from_3_2() -> None:
    old_doc = DocParseResult()
    apply_enterprise_module_overlays("3.0r1", old_doc, DkallParseResult())
    assert "oidc-sso" not in old_doc.section_keywords

    doc = DocParseResult()
    apply_enterprise_module_overlays("3.2r1", doc, DkallParseResult())
    assert "client-id" in doc.section_keywords["oidc-sso"]
    assert "oidc-sso-dir" in doc.section_keywords["global"]
    assert "oidc-sso" in doc.action_matrix["http_request_actions"]
    assert "oidc-sso" in doc.action_matrix["http_response_actions"]
    assert enterprise_module_docs_url("oidc-sso").endswith("sso-openid-connect/#oidc-sso")
    assert enterprise_module_docs_url("htmldom").endswith("response-body-injection/")


def test_saml_captcha_and_bot_management_start_in_3_0() -> None:
    old_doc = DocParseResult()
    old_dkall = DkallParseResult()
    apply_enterprise_module_overlays("2.8r1", old_doc, old_dkall)
    assert "saml-sso-load" not in old_doc.section_keywords.get("global", set())
    assert "captcha" not in old_doc.section_keywords
    assert "botmgmt-profile" not in old_doc.section_keywords
    assert "botmgmt" not in old_dkall.filters

    doc = DocParseResult()
    dkall = DkallParseResult()
    apply_enterprise_module_overlays("3.0r1", doc, dkall)
    assert "saml-sso-load" in doc.section_keywords["global"]
    assert "saml-sso" in doc.action_matrix["http_request_actions"]
    assert "saml-sso" in doc.action_matrix["http_response_actions"]
    assert "saml-sso" not in doc.action_matrix.get("http_after_response_actions", set())
    assert {"mode", "site-key", "secret-key"} <= doc.section_keywords["captcha"]
    assert "cookie-path" not in doc.section_keywords["captcha"]
    assert {"score-version", "track-defaults"} <= doc.section_keywords["botmgmt-profile"]
    assert "botmgmt-data-file" in doc.section_keywords["global"]
    assert "botmgmt-evaluate" in doc.action_matrix["http_request_actions"]
    assert "botmgmt" in dkall.filters


def test_hapee_3_2_adds_waf_profiles_captcha_options_and_rhi() -> None:
    doc = DocParseResult()
    dkall = DkallParseResult()
    apply_enterprise_module_overlays("3.2r1", doc, dkall)
    assert {"body-limit", "rules-file", "analyze-acl"} <= doc.section_keywords["waf-profile"]
    assert {"analyzer-cache", "rules-path"} <= doc.section_keywords["waf-global"]
    assert "waf-evaluate" in doc.action_matrix["http_request_actions"]
    assert "waf" in dkall.filters
    assert {"cookie-path", "on-error"} <= doc.section_keywords["captcha"]
    assert "saml-sso" in doc.action_matrix["http_after_response_actions"]
    assert {
        "hold-time",
        "local-as",
        "neighbor",
        "rhi-announce",
        "timeout graceful-restart",
    } <= doc.section_keywords["rhi-bgp"]
    assert enterprise_module_docs_url("saml-sso").endswith("sso-saml-native/#saml-sso")
    assert enterprise_module_docs_url("rhi-announce").endswith(
        "route-health-injection/#rhi-announce"
    )
