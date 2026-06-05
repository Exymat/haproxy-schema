"""Detect configuration.txt layout differences across HAProxy versions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DocLayout:
    """Which documentation structure is used in a configuration.txt file."""

    actions: str  # "modern" (§4.3/§4.4) or "legacy" (inline under §4.2)
    standalone: str  # "chapter12" or "chapter3"


def detect_doc_layout(lines: list[str]) -> DocLayout:
    from .doc_parser import _find_body_section

    has_actions_reference = _find_body_section(lines, "4.4") >= 0
    has_chapter12_userlists = _find_body_section(lines, "12.2") >= 0
    # Legacy docs (2.x / 3.0) document peers at §3.5; 3.2+ moved userlists to chapter 12.
    has_chapter3_peers = _find_body_section(lines, "3.5") >= 0
    if has_chapter12_userlists:
        standalone = "chapter12"
    elif has_chapter3_peers:
        standalone = "chapter3"
    else:
        standalone = "chapter12"
    return DocLayout(
        actions="modern" if has_actions_reference else "legacy",
        standalone=standalone,
    )
