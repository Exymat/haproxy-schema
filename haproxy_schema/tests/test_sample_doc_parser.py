from __future__ import annotations

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
