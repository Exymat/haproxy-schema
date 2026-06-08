"""Parse HAProxy configuration.txt section 4.4 (actions reference)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re

from .dconv_bridge import (
    collect_signature_lines,
    extract_description_after_header,
    extract_keyword_name,
    is_description_stop_line,
    is_valid_keyword_name,
    match_dconv_keyword_line,
)

_USABLE_HEADER_RE = re.compile(r"^\s*Usable in:\s*(.+)$", re.I)
_MARKS_LINE_RE = re.compile(r"^\s+[-Xx| ]+\s*$")

# Column labels in "Usable in:" rows (4.3 / 4.4) -> HAProxy ruleset phrase used in configs.
_COLUMN_RULESETS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"quic\s*ini", re.I), "quic-initial"),
    (re.compile(r"tcp\s*rqcon", re.I), "tcp-request connection"),
    (re.compile(r"tcp\s*rqses", re.I), "tcp-request session"),
    (re.compile(r"tcp\s*rqcnt", re.I), "tcp-request content"),
    (re.compile(r"tcp\s*rscnt", re.I), "tcp-response content"),
    (re.compile(r"http\s*req", re.I), "http-request"),
    (re.compile(r"http\s*res", re.I), "http-response"),
    (re.compile(r"http\s*aft", re.I), "http-after-response"),
    (re.compile(r"^res$", re.I), "http-response"),
    (re.compile(r"^aft$", re.I), "http-after-response"),
)

# Map ruleset phrases to schema keyword_groups keys (see doc_parser.ACTION_MATRIX_GROUP_KEYS).
RULESET_TO_ACTION_GROUP: dict[str, str] = {
    "quic-initial": "quic_initial_actions",
    "tcp-request connection": "tcp_request_actions",
    "tcp-request session": "tcp_request_actions",
    "tcp-request content": "tcp_request_actions",
    "tcp-response content": "tcp_response_actions",
    "http-request": "http_request_actions",
    "http-response": "http_response_actions",
    "http-after-response": "http_after_response_actions",
}


@dataclass
class ActionDoc:
    name: str
    signature: str
    description: str = ""
    rulesets: list[str] = field(default_factory=list)
    usable_in: str = ""
    docs_keyword: str = ""
    chapter: str = ""


def _find_body_section(lines: list[str], section_id: str) -> int:
    pattern = re.compile(rf"^{re.escape(section_id)}(?!\d)\.\s+\S")
    for idx, line in enumerate(lines):
        if not pattern.match(line.strip()):
            continue
        for offset in range(1, 4):
            if idx + offset < len(lines) and set(lines[idx + offset].strip()) == {"-"}:
                return idx
    return -1


def _parse_usable_in_block(header_content: str, marks_line: str) -> list[str]:
    """Parse the two-line Usable in matrix (header row + X marks row)."""
    columns = [part.strip() for part in header_content.split("|")]
    marks = [part.strip().lower() for part in marks_line.split("|")]
    rulesets: list[str] = []
    for column, mark in zip(columns, marks):
        if "x" not in mark:
            continue
        for pattern, ruleset in _COLUMN_RULESETS:
            if pattern.search(column):
                if ruleset not in rulesets:
                    rulesets.append(ruleset)
                break
    return rulesets


def _match_action_header(line: str) -> tuple[str, str] | None:
    dconv = match_dconv_keyword_line(line)
    if dconv:
        signature = dconv[1]
        name = extract_keyword_name(signature)
        if is_valid_keyword_name(name):
            return name, signature
        return None

    stripped = line.strip()
    if not stripped or line.startswith(" "):
        return None
    if set(stripped) <= {"-"}:
        return None
    if stripped.startswith("/*") or re.match(r"^\d+\.\d+\.", stripped):
        return None
    # Single-token action names without parameters (e.g. "accept", "allow").
    if re.fullmatch(r"[a-z][a-z0-9_.-]*", stripped):
        return stripped, stripped
    return None


def parse_actions_lines(lines: list[str], start_idx: int, end_idx: int) -> dict[str, ActionDoc]:
    actions: dict[str, ActionDoc] = {}
    idx = start_idx
    while idx < end_idx:
        matched = _match_action_header(lines[idx])
        if not matched:
            idx += 1
            continue

        signatures, scan = collect_signature_lines(lines, idx)
        name = extract_keyword_name(signatures[0])
        signature = signatures[0]
        usable_in = ""
        rulesets: list[str] = []
        while scan < end_idx and lines[scan].strip() and lines[scan].startswith(" "):
            header_match = _USABLE_HEADER_RE.match(lines[scan])
            if header_match:
                usable_in = lines[scan].strip()
                marks_idx = scan + 1
                while marks_idx < end_idx and not lines[marks_idx].strip():
                    marks_idx += 1
                if marks_idx < end_idx and _MARKS_LINE_RE.match(lines[marks_idx]):
                    rulesets = _parse_usable_in_block(header_match.group(1), lines[marks_idx])
            scan += 1

        description = extract_description_after_header(lines, idx)
        entry = actions.get(name)
        if entry is None:
            actions[name] = ActionDoc(
                name=name,
                signature=signature,
                description=description,
                rulesets=rulesets,
                usable_in=usable_in,
                docs_keyword=name,
                chapter="4.4",
            )
        else:
            if description and not entry.description:
                entry.description = description
            elif signature and signature != entry.signature:
                entry.signature = signature
            if not entry.docs_keyword:
                entry.docs_keyword = name
            if not entry.chapter:
                entry.chapter = "4.4"
            for ruleset in rulesets:
                if ruleset not in entry.rulesets:
                    entry.rulesets.append(ruleset)
        idx = scan
    return actions


_ACTION_GROUP_KEYS = (
    "quic_initial_actions",
    "tcp_request_actions",
    "tcp_response_actions",
    "http_request_actions",
    "http_response_actions",
    "http_after_response_actions",
)


def action_matrix_from_reference(actions: dict[str, ActionDoc]) -> dict[str, set[str]]:
    """Build keyword_groups-style action buckets from section 4.4 rulesets."""
    out: dict[str, set[str]] = {name: set() for name in _ACTION_GROUP_KEYS}
    for doc in actions.values():
        for ruleset in doc.rulesets:
            group = RULESET_TO_ACTION_GROUP.get(ruleset)
            if group:
                out[group].add(doc.name)
    return out


def merge_action_matrices(
    matrix_a: dict[str, set[str]],
    matrix_b: dict[str, set[str]],
) -> dict[str, set[str]]:
    keys = set(matrix_a.keys()) | set(matrix_b.keys())
    return {key: set(matrix_a.get(key, set())) | set(matrix_b.get(key, set())) for key in keys}


def parse_actions(path: Path) -> dict[str, ActionDoc]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = _find_body_section(lines, "4.4")
    end = _find_body_section(lines, "5")
    if end < 0:
        end = len(lines)
    if start < 0:
        return {}
    return parse_actions_lines(lines, start + 1, end)
