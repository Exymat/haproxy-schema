from haproxy_schema.example_docs import extract_example_at, extract_example_blocks
from haproxy_schema.language_data import build_from_paths

from ._paths import dkall_dump, haproxy_configuration_txt


def test_extract_indented_multi_line_example() -> None:
    lines = [
        "  Example:",
        "      # those are all strictly equivalent:",
        "      log-format %{+Q}o\\ %t\\ %s\\ %{-Q}r",
        "      log-format \"%{+Q}o %t %s %{-Q}r\"",
        "",
        "  See also: foo",
    ]
    examples = extract_example_blocks(lines, 0, len(lines))
    assert len(examples) == 1
    assert "# those are all strictly equivalent:" in examples[0].code
    assert 'log-format "%{+Q}o %t %s %{-Q}r"' in examples[0].code
    assert examples[0].title == ""


def test_extract_example_with_title() -> None:
    lines = [
        "  Example: Minimal configuration",
        "",
        "      global",
        "       stats socket /tmp/socket",
        "  See also: foo",
    ]
    examples = extract_example_blocks(lines, 0, len(lines))
    assert len(examples) == 1
    assert examples[0].title == "Minimal configuration"
    assert "global" in examples[0].code
    assert "stats socket /tmp/socket" in examples[0].code


def test_extract_inline_example_on_header_line() -> None:
    lines = [
        "  Example :  bind :8443 ssl crt example.pem",
        "",
        "  See also: foo",
    ]
    examples = extract_example_blocks(lines, 0, len(lines))
    assert len(examples) == 1
    assert examples[0].title == ""
    assert "bind :8443 ssl crt example.pem" in examples[0].code


def test_extract_multiple_examples() -> None:
    lines = [
        "  Example:",
        "",
        "    global",
        "      grace 10s",
        "",
        "  Please note that prose continues.",
        "",
        "  Example:",
        "",
        "    frontend ext-check",
        "      bind :9999",
    ]
    examples = extract_example_blocks(lines, 0, len(lines))
    assert len(examples) == 2
    assert "grace 10s" in examples[0].code
    assert "frontend ext-check" in examples[1].code


def test_prefixed_examples_header_not_matched() -> None:
    lines = [
        "  TCP/HTTP Examples :",
        "        balance roundrobin",
        "        balance url_param userid",
    ]
    examples = extract_example_blocks(lines, 0, len(lines))
    assert examples == []


def test_extract_example_at_returns_next_index() -> None:
    lines = [
        "  Example:",
        "      foo bar",
        "  See also: baz",
    ]
    parsed, next_idx = extract_example_at(lines, 0, len(lines))
    assert parsed is not None
    assert parsed.code == "foo bar"
    assert next_idx == 2


def test_build_language_data_grace_examples() -> None:
    doc = haproxy_configuration_txt("3.4")
    dkall = dkall_dump("3.4")
    if not doc.is_file() or not dkall.is_file():
        return

    data = build_from_paths(doc, dkall, "3.4")
    grace = data.keywords.get("grace")
    assert grace is not None
    assert len(grace.examples) >= 2
    assert any("grace 10s" in example.code for example in grace.examples)
    assert any("proc.stopping" in example.code for example in grace.examples)
