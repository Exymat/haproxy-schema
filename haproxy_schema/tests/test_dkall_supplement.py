from haproxy_schema.dkall_parser import parse_dkall
from haproxy_schema.dkall_supplement import supplement_missing_tls_options
from haproxy_schema.doc_parser import parse_configuration
from haproxy_schema.merge import merge_schema

from ._paths import dkall_dump, haproxy_configuration_txt


def test_supplement_restores_ssl_server_options_when_missing() -> None:
    dkall_path = dkall_dump("3.2")
    if not dkall_path.is_file():
        return

    dkall = parse_dkall(dkall_path)
    dkall.server_options.discard("ssl")
    dkall.bind_options.discard("ssl")

    supplement_missing_tls_options(dkall, dkall_path.parent)
    assert "ssl" in dkall.server_options
    assert "verify" in dkall.server_options
    assert "ssl" in dkall.bind_options


def test_3_4_dkall_includes_ssl_server_options() -> None:
    dkall_path = dkall_dump("3.4")
    if not dkall_path.is_file():
        return

    dkall = parse_dkall(dkall_path)
    assert "ssl" in dkall.server_options
    assert "verify" in dkall.server_options


def test_merge_schema_3_4_keyword_groups_include_ssl() -> None:
    doc_path = haproxy_configuration_txt("3.4")
    dkall_path = dkall_dump("3.4")
    if not doc_path.is_file() or not dkall_path.is_file():
        return

    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    schema = merge_schema("3.4", doc, dkall, dkall_package_dir=dkall_path.parent)

    server_opts = set(schema.keyword_groups["server_options"])
    assert "ssl" in server_opts
    assert "verify" in server_opts
