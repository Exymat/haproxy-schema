from pathlib import Path

from haproxy_schema.dconv_bridge import (
    extract_description_after_header,
    match_dconv_keyword_line,
    walk_keyword_docs,
)


def test_match_dconv_keyword_line() -> None:
    assert match_dconv_keyword_line("mode { tcp|http|log }") == ("mode", "mode { tcp|http|log }")
    assert match_dconv_keyword_line("balance <algorithm> [ <arguments> ]") is not None
    assert match_dconv_keyword_line("  indented") is None


def test_extract_description() -> None:
    lines = [
        "mode { tcp|http|log }",
        "  Set the running mode or protocol of the instance",
        "  May be used in sections :   defaults | frontend",
    ]
    assert extract_description_after_header(lines, 0) == "Set the running mode or protocol of the instance"


def test_walk_keyword_docs() -> None:
    content = """4.2. Alphabetically sorted keywords reference
---------------------------------------------

mode { tcp|http|log }
  Define the operating mode.

balance <algorithm> [ <arguments> ]
  Define load balancing.
"""
    lines = content.splitlines()
    docs = walk_keyword_docs(lines, 2, len(lines), "4.2")
    assert "mode" in docs
    assert docs["mode"].description == "Define the operating mode."
    assert "balance" in docs
