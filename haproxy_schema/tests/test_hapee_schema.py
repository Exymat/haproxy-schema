from __future__ import annotations

import json

from haproxy_schema.hapee_versions import HAPEE_OSS_BASES, HAPEE_RELEASES

from ._paths import hapee_language, hapee_schema, haproxy_vscode_root


import pytest


@pytest.mark.parametrize("oss_base", HAPEE_OSS_BASES)
def test_checked_in_hapee_schema_includes_module_keywords(oss_base: str) -> None:
    release = HAPEE_RELEASES[f"{oss_base}r1"]
    schema_path = hapee_schema(release.version)
    assert schema_path.is_file(), f"missing HAPEE schema artifact: {schema_path}"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["version"] == release.version
    assert "module-load" in schema["keywords"]
    assert "module-path" in schema["keywords"]
    assert "module-load" in schema["sections"]["global"]["keywords"]
    assert "module-path" in schema["sections"]["global"]["keywords"]
    oss_path = haproxy_vscode_root() / "schemas" / f"haproxy-{oss_base}.schema.json"
    assert oss_path.is_file(), f"missing OSS schema: {oss_path}"
    oss = json.loads(oss_path.read_text(encoding="utf-8"))
    assert "module-load" not in oss["keywords"]
    assert "module-path" not in oss["keywords"]
    for name in ("wurfl-data-file", "51degrees-data-file", "saml-sso-load"):
        if name in schema["keywords"]:
            assert name not in oss["keywords"]
    assert set(oss["keywords"]) <= set(schema["keywords"])
    for section, item in oss["sections"].items():
        assert set(item["keywords"]) <= set(schema["sections"][section]["keywords"]), section
    for group, names in oss["keyword_groups"].items():
        assert set(names) <= set(schema["keyword_groups"].get(group, [])), group
    for group in ("sample_fetches", "sample_converters"):
        assert set(oss[group]) <= set(schema[group])
        assert all(name == name.strip() and not any(char.isspace() for char in name) for name in schema[group])


def test_hapee_3_2r1_includes_has_ctl_converter() -> None:
    schema_path = hapee_schema("3.2r1")
    assert schema_path.is_file(), f"missing HAPEE schema artifact: {schema_path}"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    converters = schema.get("sample_converters") or {}
    groups = (schema.get("keyword_groups") or {}).get("sample_converters") or []
    assert "has_ctl" in converters
    assert "has_ctl" in groups
    oss_path = haproxy_vscode_root() / "schemas" / "haproxy-3.2.schema.json"
    assert oss_path.is_file()
    oss = json.loads(oss_path.read_text(encoding="utf-8"))
    assert "has_ctl" not in (oss.get("sample_converters") or {})


def test_hapee_3_2r1_includes_optional_module_overlays() -> None:
    schema = json.loads(hapee_schema("3.2r1").read_text(encoding="utf-8"))
    assert "udp-lb" in schema["sections"]
    assert "dgram-bind" in schema["sections"]["udp-lb"]["keywords"]
    assert "oidc-sso" in schema["sections"]
    assert "client-id" in schema["sections"]["oidc-sso"]["keywords"]
    assert "oidc-sso" in schema["keyword_groups"]["http_request_actions"]
    assert "oidc-sso" in schema["keyword_groups"]["http_response_actions"]
    assert "saml-sso" in schema["keyword_groups"]["http_after_response_actions"]
    assert "saml-sso-load" in schema["sections"]["global"]["keywords"]
    assert "captcha" in schema["sections"]
    assert "on-error" in schema["sections"]["captcha"]["keywords"]
    assert "botmgmt-profile" in schema["sections"]
    assert "botmgmt-evaluate" in schema["keyword_groups"]["http_request_actions"]
    assert "waf-profile" in schema["sections"]
    assert "waf-evaluate" in schema["keyword_groups"]["http_request_actions"]
    assert "rhi-bgp" in schema["sections"]
    assert "rhi-announce" in schema["sections"]["rhi-bgp"]["keywords"]
    assert {"htmldom", "botmgmt", "waf"} <= set(schema["keyword_groups"]["filters"])


def test_hapee_artifacts_preserve_optional_module_release_boundaries() -> None:
    old = json.loads(hapee_schema("2.8r1").read_text(encoding="utf-8"))
    assert "saml-sso-load" not in old["sections"]["global"]["keywords"]
    assert "captcha" not in old["sections"]
    assert "botmgmt-profile" not in old["sections"]

    schema = json.loads(hapee_schema("3.0r1").read_text(encoding="utf-8"))
    assert "saml-sso-load" in schema["sections"]["global"]["keywords"]
    assert "saml-sso" in schema["keyword_groups"]["http_request_actions"]
    assert "captcha" in schema["sections"]
    assert "site-key" in schema["sections"]["captcha"]["keywords"]
    assert "botmgmt-profile" in schema["sections"]
    assert "botmgmt" in schema["keyword_groups"]["filters"]
    assert "waf-profile" not in schema["sections"]
    assert "rhi-bgp" not in schema["sections"]


def test_hapee_language_uses_enterprise_docs_url() -> None:
    language_path = hapee_language("3.2r1")
    assert language_path.is_file(), f"missing HAPEE language artifact: {language_path}"
    language = json.loads(language_path.read_text(encoding="utf-8"))
    assert language["version"] == "3.2r1"
    assert language["docsBaseUrl"].startswith(
        "https://www.haproxy.com/documentation/haproxy-configuration-manual/3-2r1"
    )
    module_load = language["keywords"]["module-load"]
    assert "3.5-module-load" in module_load["docsUrl"]
    converters = {item["name"] for item in language["groups"]["sample_converters"]}
    assert "has_ctl" in converters
    stick_values = {
        value["name"]
        for param in language["keywords"]["stick-table type"]["arguments"]
        for value in param["values"]
    }
    assert {"ip", "ipv4", "ipv6"} <= stick_values
