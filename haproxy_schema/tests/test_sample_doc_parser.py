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
    assert "lower" in result.converters
    assert result.converters["lower"].signature == "lower"
    assert result.converters["lower"].description
