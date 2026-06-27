from __future__ import annotations

from haproxy_schema.line_layout import (
    KNOWN_PREFIX_FAMILIES,
    KNOWN_SECTION_HEADERS,
    build_line_layout,
    prefix_subcommands,
)
from haproxy_schema.options_metadata import collect_options_with_value, option_takes_value


def test_prefix_subcommands_extracts_multi_token_keywords() -> None:
    keywords = ["stats socket", "stats show", "tcp-request content", "mode"]
    assert prefix_subcommands(keywords, "stats") == ["show", "socket"]
    assert prefix_subcommands(keywords, "tcp-request") == ["content"]


def test_build_line_layout_includes_known_families() -> None:
    keywords = [
        "stats socket",
        "timeout connect",
        "tcp-check connect",
        "http-check connect",
        "capture request header",
        "tcp-request content",
        "tcp-response content",
    ]
    layout = build_line_layout(keywords)
    assert layout["prefix_families"] == list(KNOWN_PREFIX_FAMILIES)
    assert layout["section_headers"] == list(KNOWN_SECTION_HEADERS)
    assert "socket" in layout["prefix_subcommands"]["stats"]
    assert "content" in layout["tcp_request_phases"]
    assert layout["stats_socket_levels"] == ["admin", "operator", "user"]


def test_option_takes_value_heuristics() -> None:
    assert option_takes_value("httplog", ["httplog"]) is False
    assert option_takes_value("crt", ["crt <path>"]) is True
    assert "crt" in collect_options_with_value(
        ["httplog", "crt"],
        {"httplog": ["httplog"], "crt": ["crt <path>"]},
    )


def test_known_section_headers_include_compatibility_shims() -> None:
    assert "log-profile" in KNOWN_SECTION_HEADERS
