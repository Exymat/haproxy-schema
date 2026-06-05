"""Parse rule actions from pre-3.0 configuration.txt (inline under proxy keywords in §4.2)."""

from __future__ import annotations

import re

from .action_parser import (
    ActionDoc,
    RULESET_TO_ACTION_GROUP,
    action_matrix_from_reference,
    merge_action_matrices,
)

_SUPPORTED_HEADER_RE = re.compile(r"^\s+supported:\s*$", re.I)
_SUPPORTED_LINE_RE = re.compile(r"^\s+-\s+(.+)$")

# Ruleset overview lines in legacy docs (column 0, before the "supported:" list).
_LEGACY_RULESET_OVERVIEWS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^http-request\s+<action>", re.I), "http-request"),
    (re.compile(r"^http-response\s+<action>", re.I), "http-response"),
    (re.compile(r"^http-after-response\s+<action>", re.I), "http-after-response"),
    (re.compile(r"^tcp-request\s+connection\s+<action>", re.I), "tcp-request connection"),
    (re.compile(r"^tcp-request\s+session\s+<action>", re.I), "tcp-request session"),
    (re.compile(r"^tcp-request\s+content\s+<action>", re.I), "tcp-request content"),
    (re.compile(r"^tcp-response\s+content\s+<action>", re.I), "tcp-response content"),
    (re.compile(r"^quic-initial\s+<action>", re.I), "quic-initial"),
)

# Prefixes for per-action reference entries embedded in §4.2 (e.g. "http-request add-acl(...)").
_LEGACY_ACTION_DOC_PREFIXES: tuple[str, ...] = tuple(ruleset for _, ruleset in _LEGACY_RULESET_OVERVIEWS)


def uses_legacy_action_layout(lines: list[str]) -> bool:
    """True when configuration.txt has no §4.4 actions reference (HAProxy before 3.0)."""
    from .doc_parser import _find_body_section

    return _find_body_section(lines, "4.4") < 0


def is_legacy_action_doc_keyword(name: str) -> bool:
    lowered = name.lower()
    for prefix in _LEGACY_ACTION_DOC_PREFIXES:
        if lowered.startswith(f"{prefix} "):
            return True
    return False


def _normalize_supported_action(raw: str) -> str | None:
    text = raw.strip()
    if not text:
        return None
    text = re.sub(r"\s+\.\.\.$", "", text).strip()
    match = re.match(r"^([a-z][a-z0-9_-]*(?:\([^)]*\))?)", text, re.I)
    if not match:
        return None
    token = match.group(1)
    paren = token.find("(")
    return token[:paren] if paren >= 0 else token


def _matrix_from_supported_blocks(
    lines: list[str],
    start_idx: int,
    end_idx: int,
) -> dict[str, set[str]]:
    from .doc_parser import ACTION_MATRIX_GROUP_KEYS

    matrix: dict[str, set[str]] = {name: set() for name in ACTION_MATRIX_GROUP_KEYS}
    idx = start_idx
    while idx < end_idx:
        stripped = lines[idx].strip()
        ruleset: str | None = None
        for pattern, phrase in _LEGACY_RULESET_OVERVIEWS:
            if pattern.match(stripped):
                ruleset = phrase
                break
        if ruleset is None:
            idx += 1
            continue

        group = RULESET_TO_ACTION_GROUP.get(ruleset)
        if group is None:
            idx += 1
            continue

        scan = idx + 1
        found_supported = False
        while scan < end_idx:
            if _SUPPORTED_HEADER_RE.match(lines[scan]):
                action_idx = scan + 1
                while action_idx < end_idx:
                    action_match = _SUPPORTED_LINE_RE.match(lines[action_idx])
                    if not action_match:
                        break
                    action = _normalize_supported_action(action_match.group(1))
                    if action:
                        matrix[group].add(action)
                    action_idx += 1
                idx = action_idx
                found_supported = True
                break
            if lines[scan].strip() and not lines[scan].startswith(" "):
                break
            scan += 1
        if not found_supported:
            idx += 1
    return matrix


def _parse_legacy_action_reference(
    lines: list[str],
    start_idx: int,
    end_idx: int,
) -> dict[str, ActionDoc]:
    from .dconv_bridge import extract_description_after_header

    actions: dict[str, ActionDoc] = {}
    for prefix in _LEGACY_ACTION_DOC_PREFIXES:
        needle = f"{prefix} "
        for idx in range(start_idx, end_idx):
            line = lines[idx]
            if not line.strip() or line.startswith(" "):
                continue
            if not line.lower().startswith(needle):
                continue
            action_name = _normalize_supported_action(line[len(prefix) :].strip())
            if not action_name:
                continue
            chunk_end = idx + 1
            while chunk_end < end_idx:
                nxt = lines[chunk_end]
                if nxt.strip() and not nxt.startswith(" "):
                    break
                chunk_end += 1
            description = extract_description_after_header(lines, idx)
            entry = actions.get(action_name)
            if entry is None:
                actions[action_name] = ActionDoc(
                    name=action_name,
                    signature=line.strip(),
                    description=description,
                    rulesets=[prefix],
                )
            else:
                if description and not entry.description:
                    entry.description = description
                if prefix not in entry.rulesets:
                    entry.rulesets.append(prefix)
    return actions


def parse_legacy_proxy_actions(
    lines: list[str],
    section_42_start: int,
    section_end: int,
) -> tuple[dict[str, ActionDoc], dict[str, set[str]]]:
    """Extract action reference and matrix from legacy §4.2 proxy keyword docs."""
    body_start = section_42_start + 1
    supported_matrix = _matrix_from_supported_blocks(lines, body_start, section_end)
    action_reference = _parse_legacy_action_reference(lines, body_start, section_end)
    reference_matrix = action_matrix_from_reference(action_reference)
    action_matrix = merge_action_matrices(supported_matrix, reference_matrix)
    return action_reference, action_matrix
