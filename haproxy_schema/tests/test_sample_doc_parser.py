from __future__ import annotations

from pathlib import Path

import pytest

from haproxy_schema.sample_doc_parser import parse_sample_reference

from ._paths import haproxy_configuration_txt


def test_parse_sample_reference_from_configuration_txt() -> None:
    path = haproxy_configuration_txt("3.4")
    if not path.is_file():
        pytest.skip("missing 3.4 configuration.txt")

    result = parse_sample_reference(path)
    assert "hdr" in result.fetches
    assert result.fetches["hdr"].signature.startswith("hdr(")
    assert result.fetches["hdr"].description
    assert result.fetches["req.hdr_cnt"].description.startswith("Returns an integer value")
    assert result.fetches["hdr_cnt"].deprecated is True
    assert "(deprecated)" in result.fetches["hdr_cnt"].signature.lower()
    assert "lower" in result.converters
    assert result.converters["lower"].signature == "lower"
    assert result.converters["lower"].description


def test_parse_sample_reference_from_2_6_configuration_txt() -> None:
    path = haproxy_configuration_txt("2.6")
    if not path.is_file():
        pytest.skip("missing 2.6 configuration.txt")

    result = parse_sample_reference(path)
    assert result.fetches["req.hdr_cnt"].description.startswith("Returns an integer value")
    assert result.fetches["hdr_cnt"].deprecated is True
    assert result.fetches["sc_conn_cnt"].description.startswith("Returns the cumulative number")
    assert result.fetches["sc0_conn_cnt"].description.startswith("Returns the cumulative number")
    assert result.converters["add"].description.startswith("Adds <value>")


def test_parse_sample_reference_ignores_example_tables_after_summary(tmp_path: Path) -> None:
    content = """7.3.1. Converter keywords reference
----------------------------------

Keyword                                         Input type   Output type
lower                                           string       string
-- keyword -------------------------------------+- input type + output type -

The detailed list of converter keywords follows:

lower
  Converts a string to lower case.

  Example :

     # this is a comment and is ignored
        2.22.246.0/23    United Kingdom      \\n

    str      | end          | map_end
   +--------------+---------------------------------------------------------+
   | ES256        | ECDSA using P-256 and SHA-256                           |
   +--------------+---------------------------------------------------------+

7.3.2. Fetch keywords reference
-------------------------------

Keyword   Output type
src       ip

The detailed list of fetch keywords follows:

src : ip
  Returns the source address.
"""
    path = tmp_path / "configuration.txt"
    path.write_text(content, encoding="utf-8")

    result = parse_sample_reference(path)
    assert set(result.converters) == {"lower"}
    assert "src" in result.fetches
    assert "|" not in result.converters
    assert "ES256" not in result.converters
    assert "str" not in result.converters
    assert "2.22.246.0/23" not in result.converters


def test_parse_sample_reference_keeps_multiple_paragraphs(tmp_path: Path) -> None:
    content = """7.3.1. Converter keywords reference
----------------------------------

Keyword  Input type  Output type
lower    string      string

Detailed list of converters

lower
  Converts a string to lower case.

  This second paragraph must remain.

7.3.2. Fetch keywords reference
-------------------------------
"""
    path = tmp_path / "configuration.txt"
    path.write_text(content, encoding="utf-8")

    result = parse_sample_reference(path)
    assert result.converters["lower"].description == (
        "Converts a string to lower case.\n\nThis second paragraph must remain."
    )
