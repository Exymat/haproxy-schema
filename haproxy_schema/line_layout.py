"""Derive line-layout metadata for IDE token classification from keyword inventory."""

from __future__ import annotations

from typing import Iterable

KNOWN_PREFIX_FAMILIES = (
    "stats",
    "timeout",
    "tcp-check",
    "http-check",
    "capture",
    "tcp-request",
    "tcp-response",
)

KNOWN_SECTION_HEADERS = (
    "global",
    "defaults",
    "frontend",
    "backend",
    "listen",
    "peers",
    "userlist",
    "resolvers",
    "mailers",
    "program",
    "http-errors",
    "ring",
    "cache",
    "crt-list",
    "crt-store",
    "traces",
    "acme",
    "log-forward",
    # Compatibility shim for newer upstream examples until schema sections expose it.
    "log-profile",
)

STATS_SOCKET_LEVELS = ("admin", "operator", "user")


def prefix_subcommands(keywords: Iterable[str], prefix: str) -> list[str]:
    needle = f"{prefix.lower()} "
    subs: set[str] = set()
    for keyword in keywords:
        lower = keyword.lower()
        if lower.startswith(needle):
            subs.add(lower[len(needle) :])
    return sorted(subs)


def build_line_layout(keyword_names: Iterable[str]) -> dict:
    """Build prefix-family and tcp-phase metadata consumed by the VS Code extension."""
    names = list(keyword_names)
    prefix_subcommands_map: dict[str, list[str]] = {}
    active_families: list[str] = []
    for prefix in KNOWN_PREFIX_FAMILIES:
        subs = prefix_subcommands(names, prefix)
        if subs:
            prefix_subcommands_map[prefix] = subs
            active_families.append(prefix)
    return {
        "prefix_families": active_families,
        "prefix_subcommands": prefix_subcommands_map,
        "tcp_request_phases": prefix_subcommands(names, "tcp-request"),
        "tcp_response_phases": prefix_subcommands(names, "tcp-response"),
        "stats_socket_levels": list(STATS_SOCKET_LEVELS),
    }
