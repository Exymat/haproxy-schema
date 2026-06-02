"""Parse HAProxy configuration.txt section 4.4 (actions reference)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re

from .dconv_bridge import extract_description_after_header, is_description_stop_line, match_dconv_keyword_line

_ACTION_NAME = re.compile(r"^([a-z][a-z0-9_.-]*)")

_RULESET_MAP = (
    ("http-request", "HTTP Req"),
    ("http-response", "HTTP Res"),
    ("http-after-response", "HTTP Aft"),
    ("tcp-request connection", "TCP RqCon"),
    ("tcp-request session", "TCP RqSes"),
    ("tcp-request content", "TCP RqCnt"),
    ("tcp-response content", "TCP RsCnt"),
    ("quic-initial", "QUIC"),
)


@dataclass
class ActionDoc:
    name: str
    signature: str
    description: str = ""
    rulesets: list[str] = field(default_factory=list)
    usable_in: str = ""


def _find_body_section(lines: list[str], section_id: str) -> int:
    pattern = re.compile(rf"^{re.escape(section_id)}(?!\d)\.\s+\S")
    for idx, line in enumerate(lines):
        if not pattern.match(line.strip()):
            continue
        for offset in range(1, 4):
            if idx + offset < len(lines) and set(lines[idx + offset].strip()) == {"-"}:
                return idx
    return -1


def _parse_usable_in_rulesets(usable_line: str) -> list[str]:
    rulesets: list[str] = []
    for label, needle in _RULESET_MAP:
        if needle in usable_line and re.search(rf"{re.escape(needle)}[^|]*\|\s*[^|]*\bX\b", usable_line):
            rulesets.append(label)
    if not rulesets and "HTTP Req" in usable_line:
        if re.search(r"HTTP Req\|[^|]*\bX\b", usable_line):
            rulesets.append("http-request")
    return rulesets


def _match_action_header(line: str) -> tuple[str, str] | None:
    dconv = match_dconv_keyword_line(line)
    if dconv:
        name = dconv[0].split()[0]
        return name, dconv[1]
    stripped = line.strip()
    if not stripped or line.startswith(" "):
        return None
    if set(stripped) == {"-"}:
        return None
    if stripped.startswith("/*") or re.match(r"^\d+\.\d+\.", stripped):
        return None
    m = _ACTION_NAME.match(stripped)
    if not m:
        return None
    return m.group(1), stripped


def parse_actions(path: Path) -> dict[str, ActionDoc]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = _find_body_section(lines, "4.4")
    end = _find_body_section(lines, "5")
    if end < 0:
        end = len(lines)
    if start < 0:
        return {}

    actions: dict[str, ActionDoc] = {}
    idx = start + 1
    while idx < end:
        matched = _match_action_header(lines[idx])
        if not matched:
            idx += 1
            continue

        name, signature = matched
        usable_in = ""
        rulesets: list[str] = []
        scan = idx + 1
        while scan < end and lines[scan].strip() and lines[scan].startswith(" "):
            if lines[scan].strip().startswith("Usable in:"):
                usable_in = lines[scan].strip()
                rulesets = _parse_usable_in_rulesets(usable_in)
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
            )
        else:
            if description and not entry.description:
                entry.description = description
            if signature not in entry.signature:
                entry.signature = signature
        idx = scan
    return actions
