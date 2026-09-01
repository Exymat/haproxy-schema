"""Versioned syntax supplied by optional HAProxy Enterprise modules.

The Enterprise configuration manual documents the core loader, but optional
modules register their syntax at runtime and therefore do not appear in the OSS
``-dkall`` dump. Keep that syntax in an explicit overlay instead of pretending
the OSS runtime inventory is complete for HAPEE.
"""

from __future__ import annotations

from .action_parser import ActionDoc
from .dconv_bridge import KeywordDoc, KeywordVariantDoc
from .dkall_parser import DkallParseResult
from .doc_parser import DocParseResult

_ENTERPRISE_DOC_BASE = "https://www.haproxy.com/documentation/haproxy-enterprise/enterprise-modules"
_OIDC_DOC = f"{_ENTERPRISE_DOC_BASE}/single-sign-on/sso-openid-connect/"
_SAML_DOC = f"{_ENTERPRISE_DOC_BASE}/single-sign-on/sso-saml-native/"
_UDP_DOC = f"{_ENTERPRISE_DOC_BASE}/udp-load-balancing/reference/"
_HTMLDOM_DOC = f"{_ENTERPRISE_DOC_BASE}/response-body-injection/"
_RHI_DOC = f"{_ENTERPRISE_DOC_BASE}/active-active/route-health-injection/"
_BOTMGMT_DOC = "https://customer-docs.haproxy.com/bot-management/bot-management-module/"
_CAPTCHA_DOC = "https://customer-docs.haproxy.com/bot-management/captcha-modules/"
_WAF_DOC = "https://customer-docs.haproxy.com/web-application-firewall/"

_OIDC_NAMES = {
    "oidc-sso",
    "oidc-sso-dir",
    "auth-ep-uri",
    "client-id",
    "cookie-sec-1",
    "cookie-sec-2",
    "cur-cookie-sec",
    "discovery",
    "discovery-uri",
    "end-sess-ep-uri",
    "issuer",
    "jwks-uri",
    "jwt-alg",
    "logout-uri",
    "mac-secret",
    "no-referer-check",
    "post-logout-redirect-uri",
    "public-jwks-keys",
    "redirect-uri",
}
_UDP_NAMES = {
    "accepted-payload-size",
    "dgram-bind",
    "hash-balance-factor",
    "hash-type",
    "option persist",
    "option udp-check",
    "proxy-requests",
    "proxy-responses",
}
_SAML_NAMES = {"saml-sso", "saml-sso-load"}
_RHI_NAMES = {
    "hold-time",
    "local-as",
    "local-id",
    "neighbor",
    "next-hop-ipv4",
    "next-hop-ipv6",
    "rhi-announce",
    "rhi-config",
    "rhi-legacy-config",
    "timeout graceful-restart",
    "timeout keepalive",
    "timeout min-update-interval",
    "timeout open",
    "timeout reconnect",
}
_BOTMGMT_NAMES = {
    "botmgmt",
    "botmgmt-data-file",
    "botmgmt-evaluate",
    "score-version",
    "track",
    "track-defaults",
    "track-peers",
}
_CAPTCHA_NAMES = {
    "api-key",
    "cookie-domain",
    "cookie-expires",
    "cookie-max-age",
    "cookie-path",
    "cookie-samesite",
    "cookie-secure",
    "cust-html-file",
    "html-file",
    "on-error",
    "provider",
    "public-key",
    "secret-key",
    "site-key",
}
_WAF_NAMES = {
    "analyze",
    "analyze-acl",
    "analyzer-cache",
    "body-limit",
    "json-levels",
    "learning",
    "learning-mode",
    "log-host-header-len",
    "rules-file",
    "rules-path",
    "waf",
    "waf-body-limit",
    "waf-evaluate",
    "waf-load",
}


def enterprise_module_docs_url(name: str) -> str:
    if name == "htmldom":
        return _HTMLDOM_DOC
    if name in _OIDC_NAMES:
        return f"{_OIDC_DOC}#{name}"
    if name in _UDP_NAMES:
        return f"{_UDP_DOC}#{name.replace(' ', '-')}"
    if name in _SAML_NAMES:
        return f"{_SAML_DOC}#{name}"
    if name in _RHI_NAMES:
        return f"{_RHI_DOC}#{name.replace(' ', '-')}"
    if name in _BOTMGMT_NAMES:
        return _BOTMGMT_DOC
    if name in _CAPTCHA_NAMES:
        return _CAPTCHA_DOC
    if name in _WAF_NAMES:
        return _WAF_DOC
    return ""


def _add_keyword(
    doc: DocParseResult,
    name: str,
    signature: str,
    sections: tuple[str, ...],
    description: str,
) -> None:
    doc.signatures.setdefault(name, [])
    if signature not in doc.signatures[name]:
        doc.signatures[name].append(signature)
    for section in sections:
        doc.section_keywords.setdefault(section, set()).add(name)
    keyword_doc = doc.keyword_docs.setdefault(name, KeywordDoc(name=name))
    variant = KeywordVariantDoc(
        chapter="enterprise-module",
        sections=list(sections),
        signatures=[signature],
        description=description,
    )
    keyword_doc.variants.append(variant)
    doc.hapee_only_keywords.add(name)


def _add_action(
    doc: DocParseResult,
    name: str,
    signature: str,
    ruleset: str,
    group: str,
    description: str,
) -> None:
    doc.action_reference[name] = ActionDoc(
        name=name,
        signature=signature,
        description=description,
        rulesets=[ruleset],
        docs_keyword=name,
        chapter="enterprise-module",
    )
    doc.action_matrix.setdefault(group, set()).add(name)


def _extend_action(
    doc: DocParseResult,
    name: str,
    ruleset: str,
    group: str,
) -> None:
    action = doc.action_reference[name]
    if ruleset not in action.rulesets:
        action.rulesets.append(ruleset)
    doc.action_matrix.setdefault(group, set()).add(name)


def _add_udp_module(doc: DocParseResult, version: tuple[int, int]) -> None:
    directives = {
        "balance": "balance <algorithm> [arguments]",
        "dgram-bind": "dgram-bind <address>[:port]",
        "maxconn": "maxconn <connections>",
        "option tcp-check": "option tcp-check",
        "option udp-check": "option udp-check",
        "proxy-requests": "proxy-requests <number>",
        "proxy-responses": "proxy-responses <number>",
        "server": "server <name> <address>[:port] [param*]",
        "source": "source <address>[:port] [usesrc <address>]",
        "tcp-check": "tcp-check <action> [arguments]",
        "timeout client": "timeout client <timeout>",
        "timeout server": "timeout server <timeout>",
        "use-server": "use-server <server> if|unless <condition>",
    }
    if version >= (3, 0):
        directives.update(
            {
                "log": "log <address> [len <length>] [format <format>] [facility <facility>]",
                "log-tag": "log-tag <string>",
            }
        )
    if version >= (3, 1):
        directives.update(
            {
                "hash-balance-factor": "hash-balance-factor <factor>",
                "hash-type": "hash-type <method> <function> <modifier>",
            }
        )
    if version >= (3, 2):
        directives.update(
            {
                "accepted-payload-size": "accepted-payload-size <bytes>",
                "acl": "acl <name> <criterion> [flags] [operator] <value>",
                "default-server": "default-server [param*]",
                "option persist": "option persist",
            }
        )
    for name, signature in directives.items():
        _add_keyword(
            doc,
            name,
            signature,
            ("udp-lb",),
            "Directive provided by the HAProxy Enterprise UDP load-balancing module.",
        )


def _add_oidc_module(doc: DocParseResult) -> None:
    _add_keyword(
        doc,
        "oidc-sso-dir",
        "oidc-sso-dir <directory>",
        ("global",),
        "Default directory for certificates and keys used by the OpenID Connect SSO module.",
    )
    directives = {
        "auth-ep-uri": "auth-ep-uri <uri>",
        "client-id": "client-id <client-id>",
        "cookie": "cookie domain <domain> [secure] [httponly] [maxlife <life>]",
        "cookie-sec-1": "cookie-sec-1 <secret>",
        "cookie-sec-2": "cookie-sec-2 <secret>",
        "cur-cookie-sec": "cur-cookie-sec <1|2>",
        "crt": "crt <filename>",
        "discovery": "discovery <on|off>",
        "discovery-uri": "discovery-uri <uri>",
        "end-sess-ep-uri": "end-sess-ep-uri <uri>",
        "issuer": "issuer <uri>",
        "jwks-uri": "jwks-uri <uri>",
        "jwt-alg": "jwt-alg <algorithm>",
        "key": "key <filename>",
        "logout-uri": "logout-uri <uri>",
        "mac-secret": "mac-secret <secret>",
        "no-referer-check": "no-referer-check",
        "post-logout-redirect-uri": "post-logout-redirect-uri <uri>",
        "public-jwks-keys": "public-jwks-keys <filename>",
        "redirect-uri": "redirect-uri <uri>",
    }
    for name, signature in directives.items():
        _add_keyword(
            doc,
            name,
            signature,
            ("oidc-sso",),
            "Directive provided by the HAProxy Enterprise OpenID Connect SSO module.",
        )
    _add_action(
        doc,
        "oidc-sso",
        "oidc-sso <section> [if|unless <condition>]",
        "http-request",
        "http_request_actions",
        "Require authentication using a named OpenID Connect SSO section.",
    )
    # The response action shares the same name and is represented in both
    # groups; one ActionDoc retains both valid rulesets.
    _extend_action(doc, "oidc-sso", "http-response", "http_response_actions")


def _add_saml_module(doc: DocParseResult, version: tuple[int, int]) -> None:
    _add_keyword(
        doc,
        "saml-sso-load",
        "saml-sso-load <templates-directory> <configuration-file>",
        ("global",),
        "Load the templates and configuration used by the native SAML SSO module.",
    )
    _add_action(
        doc,
        "saml-sso",
        "saml-sso <application> [if|unless <condition>]",
        "http-request",
        "http_request_actions",
        "Authenticate a request using an application from the SAML module configuration.",
    )
    _extend_action(doc, "saml-sso", "http-response", "http_response_actions")
    if version >= (3, 2):
        _extend_action(doc, "saml-sso", "http-after-response", "http_after_response_actions")


def _add_waf_module(doc: DocParseResult, dkall: DkallParseResult, version: tuple[int, int]) -> None:
    # The WAF module predates all releases supported by this project.
    dkall.filters.add("waf")
    for name, signature in {
        "waf-body-limit": "waf-body-limit <bytes>",
        "waf-load": "waf-load <arguments>",
    }.items():
        _add_keyword(
            doc,
            name,
            signature,
            ("global",),
            "Directive provided by the HAProxy Enterprise Web Application Firewall module.",
        )

    if version < (3, 2):
        return

    common = {
        "body-limit": "body-limit <bytes>",
        "rules-file": "rules-file <file>",
    }
    profile = {
        **common,
        "analyze": "analyze <request|response|both>",
        "analyze-acl": "analyze-acl <acl>",
        "learning": "learning <on|off>",
        "learning-mode": "learning-mode <on|off>",
    }
    waf_global = {
        **common,
        "analyzer-cache": "analyzer-cache <entries>",
        "json-levels": "json-levels <levels>",
        "log-host-header-len": "log-host-header-len <bytes>",
        "rules-path": "rules-path <directory>",
    }
    for section, directives in (("waf-profile", profile), ("waf-global", waf_global)):
        for name, signature in directives.items():
            _add_keyword(
                doc,
                name,
                signature,
                (section,),
                "Directive provided by the HAProxy Enterprise Web Application Firewall module.",
            )
    _add_action(
        doc,
        "waf-evaluate",
        "waf-evaluate [profile <name>] [if|unless <condition>]",
        "http-request",
        "http_request_actions",
        "Evaluate a request on demand with the Enterprise Web Application Firewall.",
    )


def _add_bot_management_module(
    doc: DocParseResult,
    dkall: DkallParseResult,
) -> None:
    dkall.filters.add("botmgmt")
    _add_keyword(
        doc,
        "botmgmt-data-file",
        "botmgmt-data-file <file>",
        ("global",),
        "Load the reputation data used by the HAProxy Enterprise Bot Management module.",
    )
    for name, signature in {
        "score-version": "score-version <version>",
        "source": "source <type> <sample-expression>",
        "track": "track <mode>",
        "track-defaults": "track-defaults [size <entries>] [expire <time>] [period <time>]",
        "track-peers": "track-peers <peers-section>",
    }.items():
        _add_keyword(
            doc,
            name,
            signature,
            ("botmgmt-profile",),
            "Directive provided by the HAProxy Enterprise Bot Management module.",
        )
    _add_action(
        doc,
        "botmgmt-evaluate",
        "botmgmt-evaluate [profile <name>] [if|unless <condition>]",
        "http-request",
        "http_request_actions",
        "Evaluate a request on demand with the HAProxy Enterprise Bot Management module.",
    )


def _add_captcha_module(doc: DocParseResult, version: tuple[int, int]) -> None:
    directives = {
        "api-key": "api-key <key>",
        "cust-html-file": "cust-html-file <file>",
        "html-file": "html-file <file>",
        "mode": "mode <provider>",
        "provider": "provider <provider>",
        "public-key": "public-key <key>",
        "secret-key": "secret-key <key>",
        "site-key": "site-key <key>",
    }
    if version >= (3, 2):
        directives.update(
            {
                "cookie-domain": "cookie-domain <domain>",
                "cookie-expires": "cookie-expires <date>",
                "cookie-max-age": "cookie-max-age <seconds>",
                "cookie-path": "cookie-path <path>",
                "cookie-samesite": "cookie-samesite <strict|lax|none>",
                "cookie-secure": "cookie-secure <on|off>",
                "on-error": "on-error <allow|deny>",
            }
        )
    for name, signature in directives.items():
        _add_keyword(
            doc,
            name,
            signature,
            ("captcha",),
            "Directive provided by the HAProxy Enterprise Captcha module.",
        )


def _add_rhi_module(doc: DocParseResult) -> None:
    directives = {
        "acl": "acl <name> <criterion> [flags] [operator] <value>",
        "hold-time": "hold-time <seconds>",
        "local-as": "local-as <as-number>",
        "local-id": "local-id <ipv4-or-uint32>",
        "log": "log global|<target> [arguments]",
        "neighbor": "neighbor <name> <address> [as <number>] [local-pref <number>] [metric <number>] [source <address>] [namespace <name>] [tcp-md5sig <password>]",
        "next-hop-ipv4": "next-hop-ipv4 <address>",
        "next-hop-ipv6": "next-hop-ipv6 <address>",
        "rhi-announce": "rhi-announce auto|label <name>|addrs <network> [arguments] [if|unless <condition>]",
        "rhi-config": "rhi-config <file>",
        "rhi-legacy-config": "rhi-legacy-config <file>",
        "timeout connect": "timeout connect <timeout>",
        "timeout graceful-restart": "timeout graceful-restart <timeout>",
        "timeout keepalive": "timeout keepalive <timeout>",
        "timeout min-update-interval": "timeout min-update-interval <timeout>",
        "timeout open": "timeout open <timeout>",
        "timeout reconnect": "timeout reconnect <timeout>",
    }
    for name, signature in directives.items():
        _add_keyword(
            doc,
            name,
            signature,
            ("rhi-bgp",),
            "Directive provided by the HAProxy Enterprise Route Health Injection module.",
        )


def apply_enterprise_module_overlays(
    version: str,
    doc: DocParseResult,
    dkall: DkallParseResult,
) -> None:
    """Add optional module syntax available in the selected HAPEE release."""
    # Response-body injection predates every supported r1 release.
    dkall.filters.add("htmldom")

    base = tuple(int(part) for part in version.removesuffix("r1").split("."))
    _add_waf_module(doc, dkall, base)
    if base >= (2, 8):
        _add_udp_module(doc, base)
    if base >= (3, 0):
        _add_saml_module(doc, base)
        _add_bot_management_module(doc, dkall)
        _add_captcha_module(doc, base)
    if base >= (3, 2):
        _add_oidc_module(doc)
        _add_rhi_module(doc)
