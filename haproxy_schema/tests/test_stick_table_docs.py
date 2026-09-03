from pathlib import Path

import pytest

from haproxy_schema.doc_parser import parse_configuration
from haproxy_schema.dkall_parser import parse_dkall
from haproxy_schema.merge import merge_schema
from haproxy_schema.stick_table_docs import parse_stick_table_declaration_arguments

from ._paths import dkall_dump, haproxy_configuration_txt


def test_parse_stick_table_declaration_from_fixture(tmp_path: Path) -> None:
    content = """11.1. stick-table declaration
-----------------------------

In a "frontend", "backend" or "listen" section:

stick-table type <type> size <size> [expire <expire>] [nopurge]

Arguments: (mandatory ones first, then alphabetically sorted):
  - type <type>
             This mandatory argument sets the key type to <type>, which
             usually is a single word but may also have its own arguments:

     * ip        This type should be avoided in favor of a more explicit one such
                 as "ipv4" or "ipv6".

     * ipv4      A table declared with this type will only store IPv4 addresses.

     * string [len <len>]
                 A table declared with "type string" will store substrings.

  - size <size>
             This mandatory argument sets maximum number of entries that can
             fit in the table to <size>.

  - nopurge  indicates that we refuse to purge older entries when the table is
             full.

The data types that can be associated with an entry via the "store" directive
are listed below.

Arguments:
  - bytes_in_cnt [4 bytes]
             This is the client to server byte count.

  - gpc0 [4 bytes]
             This is the first General Purpose Counter.

  - http_req_rate(<period>) [12 bytes]
             This is a request frequency counter.

See also : "stick match".

11.2. Peers declaration
-----------------------

table <name> type <type>
"""
    path = tmp_path / "configuration.txt"
    path.write_text(content, encoding="utf-8")

    params = parse_stick_table_declaration_arguments(path.read_text(encoding="utf-8").splitlines())
    by_param = {param.parameter: param for param in params}

    assert "<type>" in by_param
    assert "own arguments" in by_param["<type>"].description
    type_names = {value.name for value in by_param["<type>"].values}
    assert type_names == {"ip", "ipv4", "string"}
    ip = next(value for value in by_param["<type>"].values if value.name == "ip")
    assert "ipv4" in ip.description
    assert "never needed" not in ip.description
    size = next(param for param in params if param.parameter.startswith("size"))
    assert "maximum number of entries" in size.description
    assert "nopurge" in by_param
    store = next(param for param in params if param.parameter.lower().startswith("store"))
    store_names = {value.name for value in store.values}
    assert "bytes_in_cnt" in store_names
    assert "gpc0" in store_names
    assert "http_req_rate(<period>)" in store_names
    gpc0 = next(value for value in store.values if value.name == "gpc0")
    assert "General Purpose Counter" in gpc0.description


def test_parse_stick_table_declaration_from_3_4_configuration_txt() -> None:
    path = haproxy_configuration_txt("3.4")
    if not path.is_file():
        pytest.skip("missing 3.4 configuration.txt")

    result = parse_configuration(path)
    stick = result.keyword_docs["stick-table type"]
    values = {value.name: value.description for param in stick.arguments for value in param.values}
    assert "ip" in values
    assert "ipv4" in values["ip"]
    assert "alias for" in values["ip"]
    assert "ipv6" in values
    assert "integer" in values
    assert "gpc0" in values
    assert "http_req_rate(<period>)" in values

    table = result.keyword_docs["table"]
    table_values = {value.name for param in table.arguments for value in param.values}
    assert "ip" in table_values
    assert "ipv4" in table_values

    dkall = dkall_dump("3.4")
    if dkall.is_file():
        schema = merge_schema("3.4", result, parse_dkall(dkall), dkall_package_dir=dkall.parent)
        type_slot = schema.keywords["stick-table type"].argument_model.slots[0]
        assert {"ip", "ipv4", "ipv6", "integer", "string", "binary"} <= set(type_slot["enum"])
        last_slot = schema.keywords["stick-table type"].argument_model.slots[-1]
        assert last_slot["variadic"] is True
        assert last_slot["enum"] == []


def test_older_docs_without_stick_table_chapter_are_unchanged() -> None:
    path = haproxy_configuration_txt("2.6")
    if not path.is_file():
        pytest.skip("missing 2.6 configuration.txt")

    lines = path.read_text(encoding="utf-8").splitlines()
    assert parse_stick_table_declaration_arguments(lines) == []
