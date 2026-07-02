from pathlib import Path

import pytest

from haproxy_schema.dconv_bridge import (
    collect_signature_lines,
    extract_description_after_header,
    extract_keyword_name,
    get_indent,
    is_signature_continuation_line,
    match_dconv_keyword_line,
    walk_keyword_docs,
)

from ._paths import haproxy_configuration_txt


def test_match_dconv_keyword_line() -> None:
    assert match_dconv_keyword_line("mode { tcp|http|log }") == ("mode", "mode { tcp|http|log }")
    assert match_dconv_keyword_line("balance <algorithm> [ <arguments> ]") is not None
    assert match_dconv_keyword_line("  indented") is None


def test_extract_keyword_name_stops_before_prefixed_placeholder() -> None:
    assert extract_keyword_name("bind /<path> [, ...] [param*]") == "bind"
    assert extract_keyword_name("stats socket /<path> [param*]") == "stats socket"


def test_extract_description() -> None:
    lines = [
        "mode { tcp|http|log }",
        "  Set the running mode or protocol of the instance",
        "  May be used in sections :   defaults | frontend",
    ]
    assert extract_description_after_header(lines, 0) == "Set the running mode or protocol of the instance"


def test_extract_description_skips_contexts_before_sections() -> None:
    lines = [
        "http-request <action> [options...] [ { if | unless } <condition> ]",
        "  Access control for Layer 7 requests",
        "",
        "  May be used in the following contexts: http",
        "",
        "  May be used in sections:   defaults | frontend | listen | backend",
        "                               yes   |    yes   |   yes  |   yes",
        "",
        "  The http-request statement defines a set of rules which apply to layer 7",
        "  processing.",
        "",
        "  Example:",
        "        http-request deny",
    ]
    text = extract_description_after_header(lines, 0)
    assert text.startswith("Access control for Layer 7 requests")
    assert "The http-request statement defines" in text


def test_extract_description_accepts_four_space_prose() -> None:
    lines = [
        "set-path <fmt>",
        "  Usable in: HTTP Req",
        "                    X",
        "",
        "    This rewrites the request path with the result of the evaluation of format",
        "    string <fmt>. The query string, if any, is left intact.",
    ]
    text = extract_description_after_header(lines, 0)
    assert "rewrites the request path" in text
    assert "query string" in text


def test_extract_description_keeps_multiple_paragraphs() -> None:
    lines = [
        "source <addr> [param*]",
        "  The first paragraph.",
        "",
        "  The second paragraph.",
        "",
        "  Arguments: none",
    ]
    assert extract_description_after_header(lines, 0) == "The first paragraph.\n\nThe second paragraph."


def test_walk_keyword_docs() -> None:
    content = """4.2. Alphabetically sorted keywords reference
---------------------------------------------

mode { tcp|http|log }
  Define the operating mode.

balance <algorithm> [ <arguments> ]
  Define load balancing.

  May be used in the following contexts: tcp, http, log
"""
    lines = content.splitlines()
    docs = walk_keyword_docs(lines, 2, len(lines), "4.2")
    assert "mode" in docs
    assert docs["mode"].description == "Define the operating mode."
    assert "balance" in docs
    assert docs["balance"].contexts == ["tcp", "http", "log"]


def test_walk_keyword_docs_keeps_same_chapter_section_variants_distinct() -> None:
    content = """4.2. Alphabetically sorted keywords reference
---------------------------------------------

bind [<address>]:<port_range> [, ...] [param*]
  Frontend/listen bind description.

  May be used in sections :   defaults | frontend | listen | backend
                                 no    |    yes   |   yes  |   no

bind [<address>]:port [param*]
  Peer bind description.
"""
    lines = content.splitlines()
    docs = walk_keyword_docs(lines, 2, len(lines), "4.2")
    bind = docs["bind"]
    assert len(bind.variants) == 2
    proxy_variant = next(variant for variant in bind.variants if "listen" in variant.sections)
    peer_variant = next(
        variant for variant in bind.variants if variant.description == "Peer bind description."
    )
    assert proxy_variant.description == "Frontend/listen bind description."
    assert proxy_variant.sections == ["frontend", "listen"]
    assert peer_variant.signatures == ["bind [<address>]:port [param*]"]


def test_walk_keyword_docs_keeps_alternative_prefixed_placeholder_signatures() -> None:
    content = """4.2. Alphabetically sorted keywords reference
---------------------------------------------

bind [<address>]:<port_range> [, ...] [param*]
bind /<path> [, ...] [param*]
  Frontend/listen bind description.

  May be used in sections :   defaults | frontend | listen | backend
                                 no    |    yes   |   yes  |   no
"""
    lines = content.splitlines()
    docs = walk_keyword_docs(lines, 2, len(lines), "4.2")
    bind = docs["bind"]
    proxy_variant = bind.variant_for("4.2")
    assert "bind [<address>]:<port_range> [, ...] [param*]" in proxy_variant.signatures
    assert "bind /<path> [, ...] [param*]" in proxy_variant.signatures


def test_collect_signature_lines_appends_continuation() -> None:
    lines = [
        "log <target> [len <length>] [format <format>]",
        "    [profile <prof>] <facility> [<level>]",
        "  Adds a global syslog server.",
    ]
    signatures, next_idx = collect_signature_lines(lines, 0)
    assert signatures == [
        "log <target> [len <length>] [format <format>] [profile <prof>] <facility> [<level>]",
    ]
    assert next_idx == 2
    assert is_signature_continuation_line(lines[1])
    assert not is_signature_continuation_line(lines[2])


def test_collect_signature_lines_appends_inner_alternative_lines() -> None:
    lines = [
        "http-error status <code> [content-type <type>]",
        "           [ { default-errorfiles | errorfile <file> | errorfiles <name> |",
        "               file <file> | lf-file <file> | string <str> | lf-string <fmt> } ]",
        "           [ hdr <name> <fmt> ]*",
        "  Defines a custom error message.",
    ]
    signatures, next_idx = collect_signature_lines(lines, 0)
    assert len(signatures) == 1
    assert "lf-string <fmt>" in signatures[0]
    assert "[ hdr <name> <fmt> ]*" in signatures[0]
    assert next_idx == 4


def test_collect_signature_lines_appends_table_tail() -> None:
    lines = [
        "table <tablename> type {ip | integer | string [len <length>] | binary [len <length>]}",
        "      size <size> [expire <expire>] [write-to <wtable>] [nopurge] [store <data_type>]*",
        "      [recv-only]",
        "  Configure a stickiness table.",
    ]
    signatures, next_idx = collect_signature_lines(lines, 0)
    assert len(signatures) == 1
    assert "size <size>" in signatures[0]
    assert "[recv-only]" in signatures[0]
    assert next_idx == 3


def test_collect_signature_lines_ignores_example_blocks() -> None:
    lines = [
        "global",
        "    # Simple configuration for an HTTP proxy",
        "  Some description.",
    ]
    signatures, next_idx = collect_signature_lines(lines, 0)
    assert signatures == ["global"]
    assert next_idx == 1
    assert not is_signature_continuation_line(lines[1])


@pytest.mark.parametrize("version", ("2.6", "2.8", "3.0", "3.2", "3.4"))
def test_configuration_txt_has_no_missed_signature_continuations(version: str) -> None:
    doc_path = haproxy_configuration_txt(version)
    if not doc_path.is_file():
        pytest.skip(f"missing HAProxy doc source: {doc_path}")

    lines = doc_path.read_text(encoding="utf-8", errors="replace").splitlines()
    missed: list[str] = []
    for idx, line in enumerate(lines):
        if not match_dconv_keyword_line(line):
            continue
        signatures, next_idx = collect_signature_lines(lines, idx)
        scan = next_idx
        while scan < len(lines):
            candidate = lines[scan]
            if not candidate.strip():
                break
            if match_dconv_keyword_line(candidate) or (candidate.strip() and not candidate.startswith(" ")):
                break
            if get_indent(candidate) >= 4 and not is_signature_continuation_line(candidate):
                stripped = candidate.strip()
                if not stripped.startswith("#"):
                    missed.append(
                        f"{version} L{idx + 1} {signatures[0][:60]}... "
                        f"missed L{scan + 1}: {stripped[:60]}"
                    )
                    break
            if candidate.startswith("  ") and not candidate.startswith("   "):
                break
            scan += 1

    assert not missed, "Missed signature continuations:\n" + "\n".join(missed[:20])
