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


def test_merge_schema_prunes_unsupported_compile_time_doc_keywords() -> None:
    version = "3.4"
    doc_path = haproxy_configuration_txt(version)
    if not doc_path.is_file():
        return

    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_dump(version))
    schema = merge_schema(version, doc, dkall, dkall_package_dir=dkall_dump(version).parent)

    assert "wurfl-data-file" not in schema.keywords
