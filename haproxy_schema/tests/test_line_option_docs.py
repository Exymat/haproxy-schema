from pathlib import Path

from haproxy_schema.doc_parser import parse_configuration
from haproxy_schema.dkall_parser import parse_dkall
from haproxy_schema.language_data import build_language_data
from haproxy_schema.line_option_docs import walk_line_option_docs
from haproxy_schema.merge import merge_schema
from haproxy_schema.tests._paths import dkall_dump, haproxy_configuration_txt


def test_walk_line_option_docs_skips_context_metadata(tmp_path: Path) -> None:
    content = """5.1. Bind options
-----------------

accept-proxy
  Enforces the use of the PROXY protocol.

idle-ping <delay>
  May be used in the following contexts: tcp, http, log

  Define an interval for periodic liveliness on idle frontend connections.

5.2. Server and default-server options
-------------------------------------

check
  May be used in the following contexts: tcp, http, log

  Enable health checks on the server.

init-state { fully-up | up | down | fully-down | none }
  May be used in the following contexts: tcp, http

  May be used in sections :   defaults | frontend | listen | backend
                                 no   |    no    |   yes  |   yes

  The init-state option sets the initial state of the server.

expose-fd listeners
  This option is only usable with the stats socket.
"""
    file_path = tmp_path / "configuration.txt"
    file_path.write_text(content, encoding="utf-8")
    lines = content.splitlines()

    bind_docs = walk_line_option_docs(lines, 0, 12, "5.1")
    server_docs = walk_line_option_docs(lines, 12, len(lines), "5.2")

    assert bind_docs["accept-proxy"].description.startswith("Enforces the use")
    assert "periodic liveliness" in bind_docs["idle-ping"].description
    assert bind_docs["idle-ping"].contexts == ["tcp", "http", "log"]
    assert "health checks" in server_docs["check"].description
    assert server_docs["check"].contexts == ["tcp", "http", "log"]
    assert "initial state" in server_docs["init-state"].description
    assert server_docs["init-state"].contexts == ["tcp", "http"]
    assert server_docs["expose-fd"].description.startswith("This option is only usable")
    assert server_docs["expose-fd listeners"].description.startswith("This option is only usable")


def test_walk_line_option_docs_keeps_multiple_paragraphs(tmp_path: Path) -> None:
    content = """5.2. Server and default-server options
-------------------------------------

source <addr>[:<port>] [usesrc { <addr2>[:<port2>] | client | clientip } ]
source <addr>[:<port>] [usesrc { <addr2>[:<port2>] | hdr_ip(<hdr>[,<occ>]) } ]
source <addr>[:<port>] [interface <name>]
  The "source" parameter sets the source address which will be used when
  connecting to the server.

  Additionally, the "source" statement on a server line allows one to specify a
  source port range.

  Since Linux 4.2/libc 2.23 IP_BIND_ADDRESS_NO_PORT is set for connections
  specifying the source address without port(s).

ssl
  Enable SSL.
"""
    lines = content.splitlines()
    docs = walk_line_option_docs(lines, 0, len(lines), "5.2")
    description = docs["source"].description
    assert 'The "source" parameter sets the source address' in description
    assert "Additionally, the \"source\" statement on a server line allows one to specify" in description
    assert "Since Linux 4.2/libc 2.23" in description
    assert "\n\n" in description


def test_walk_line_option_docs_keeps_ascii_tables(tmp_path: Path) -> None:
    content = """5.2. Server and default-server options
-------------------------------------

inter <delay>
fastinter <delay>
downinter <delay>
  May be used in the following contexts: tcp, http, log

  The "inter" parameter sets the interval between two consecutive health checks
  to <delay> milliseconds.

             Server state                   |         Interval used
    ----------------------------------------+----------------------------------
     UP 100% (non-transitional)             | "inter"
    ----------------------------------------+----------------------------------
     DOWN 100% (non-transitional)           | "downinter" if set,
                                            | "inter" otherwise.
    ----------------------------------------+----------------------------------

  Just as with every other time-based parameter, they can be entered in any
  other explicit unit.
"""
    lines = content.splitlines()
    docs = walk_line_option_docs(lines, 0, len(lines), "5.2")
    description = docs["inter"].description
    assert "Server state" in description
    assert 'UP 100% (non-transitional)             | "inter"' in description
    assert '"downinter" if set,' in description


def test_parse_configuration_populates_line_option_docs() -> None:
    doc_path = haproxy_configuration_txt("3.4")
    if not doc_path.is_file():
        return

    result = parse_configuration(doc_path)
    assert result.bind_option_docs["ssl"].description
    assert result.server_option_docs["check"].description
    assert result.bind_option_docs["expose-fd"].description


def test_language_data_includes_bind_and_server_option_descriptions() -> None:
    version = "3.4"
    doc_path = haproxy_configuration_txt(version)
    if not doc_path.is_file():
        return

    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_dump(version))
    language = build_language_data(version, doc, dkall, doc.action_reference)

    bind_ssl = next(item for item in language.groups["bind_options"] if item.name == "ssl")
    server_check = next(item for item in language.groups["server_options"] if item.name == "check")
    assert bind_ssl.description
    assert server_check.description
    assert "5.1" in bind_ssl.docsUrl
    assert "5.2" in server_check.docsUrl


def test_merge_schema_includes_context_metadata() -> None:
    version = "3.4"
    doc_path = haproxy_configuration_txt(version)
    if not doc_path.is_file():
        return

    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_dump(version))
    schema = merge_schema(version, doc, dkall, dkall_package_dir=dkall_dump(version).parent)

    assert "http" in schema.keywords["capture cookie"].contexts
    assert "log" in schema.keyword_group_contexts["server_options"]["check"]
    assert "http" in schema.keyword_group_contexts["options"]["httplog"]


def test_merge_schema_promotes_line_option_signatures_to_keywords() -> None:
    version = "3.4"
    doc_path = haproxy_configuration_txt(version)
    if not doc_path.is_file():
        return

    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_dump(version))
    schema = merge_schema(version, doc, dkall, dkall_package_dir=dkall_dump(version).parent)

    source_kw = schema.keywords["source"]
    source_variant = next(variant for variant in source_kw.variants if variant.chapter == "5.2")
    assert any(
        signature.startswith("source <addr>") and "[interface <name>]" in signature
        for signature in source_variant.signatures
    )
    assert source_variant.sections == []
    assert source_variant.argument_model is not None

    check_kw = schema.keywords["check"]
    check_variant = next(variant for variant in check_kw.variants if variant.chapter == "5.2")
    assert check_variant.signatures
    assert check_variant.sections == []
    assert check_variant.argument_model is not None


def test_merge_schema_keeps_bind_unix_path_signature_from_doc_parser() -> None:
    version = "3.4"
    doc_path = haproxy_configuration_txt(version)
    if not doc_path.is_file():
        return

    doc = parse_configuration(doc_path)
    assert "bind /<path> [, ...] [param*]" in doc.signatures["bind"]
    dkall = parse_dkall(dkall_dump(version))
    schema = merge_schema(version, doc, dkall, dkall_package_dir=dkall_dump(version).parent)

    bind_kw = schema.keywords["bind"]
    bind_variant = next(variant for variant in bind_kw.variants if variant.chapter == "4.2")
    assert "bind /<path> [, ...] [param*]" in bind_kw.signatures
    assert "bind /<path> [, ...] [param*]" in bind_variant.signatures


def test_merge_schema_keeps_nested_line_options_out_of_top_level_sections() -> None:
    version = "3.4"
    doc_path = haproxy_configuration_txt(version)
    if not doc_path.is_file():
        return

    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_dump(version))
    schema = merge_schema(version, doc, dkall, dkall_package_dir=dkall_dump(version).parent)

    verify_kw = schema.keywords["verify"]
    assert verify_kw.sections == ["crt-list"]
    bind_variant = next(variant for variant in verify_kw.variants if variant.chapter == "5.1")
    assert bind_variant.sections == []


def test_merge_schema_prunes_unsupported_compile_time_doc_keywords() -> None:
    version = "3.4"
    doc_path = haproxy_configuration_txt(version)
    if not doc_path.is_file():
        return

    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_dump(version))
    schema = merge_schema(version, doc, dkall, dkall_package_dir=dkall_dump(version).parent)

    assert "wurfl-data-file" not in schema.keywords


def test_line_option_docs_metadata_and_structured_branches() -> None:
    from haproxy_schema.line_option_docs import (
        _is_metadata_line,
        _is_structured_doc_line,
        _skip_metadata_block,
        extract_line_option_description,
    )

    assert _is_metadata_line("  May be used in the following contexts without colon") is True
    assert _is_metadata_line("  May be used in sections inline") is True
    assert _is_metadata_line("defaults | frontend | listen | backend") is True
    assert _is_metadata_line("yes | no | - | yes") is True
    assert _is_structured_doc_line("") is False
    assert _is_structured_doc_line("----------------+---------------") is True

    lines = [
        "table-opt <val>",
        "  May be used in sections : defaults | frontend",
        "                    yes | yes",
        "  Intro paragraph.",
        "",
        "  Second paragraph after blank.",
        "  | Name | Value |",
        "  +------+-------+",
        "  | foo  | bar   |",
        "  Arguments:",
        "    table-opt value",
        "  Examples:",
        "    table-opt 1",
        "  See also: ssl",
        "next-opt",
        "  Final option.",
    ]
    idx = _skip_metadata_block(lines, 1, len(lines))
    assert idx >= 1
    desc = extract_line_option_description(lines, 0, len(lines))
    assert "Intro paragraph" in desc
    assert "Name" in desc or "foo" in desc
