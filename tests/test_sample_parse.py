from pathlib import Path

from haproxy_schema.dkall_parser import parse_dkall


def test_structured_sample_fetch_and_converter(tmp_path: Path) -> None:
    content = """# List of registered sample converter functions:
lower(str): str => str
# List of registered sample fetch functions:
[ Y Y . . ] hdr([string]): str
[ Y Y . . ] url: str
"""
    path = tmp_path / "dkall.txt"
    path.write_text(content, encoding="utf-8")
    result = parse_dkall(path)

    assert "hdr" in result.sample_fetches_structured
    hdr = result.sample_fetches_structured["hdr"]
    assert hdr.args == ["string"]
    assert hdr.out_type == "str"
    assert hdr.contexts[:2] == [True, True]

    assert "lower" in result.sample_converters_structured
    lower = result.sample_converters_structured["lower"]
    assert lower.in_type == "str"
    assert lower.out_type == "str"
