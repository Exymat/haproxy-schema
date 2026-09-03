"""Parse ACL reference data from configuration.txt chapter 7.1-7.4."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re


def _find_body_section(lines: list[str], section_id: str) -> int:
    """Locate a documentation body section (same rules as doc_parser)."""
    pattern = re.compile(rf"^{re.escape(section_id)}(?!\d)\.\s+\S")
    for idx, line in enumerate(lines):
        if not pattern.match(line.strip()):
            continue
        for offset in range(1, 4):
            if idx + offset < len(lines) and set(lines[idx + offset].strip()) == {"-"}:
                return idx
    return -1


_FLAG_RE = re.compile(r"^\s*(-{1,2}[a-zA-Z]*)\s*:")
_QUOTED_METHOD_RE = re.compile(r'^\s*-\s*"([^"]+)"\s*:\s*(.*)$')
_INT_OP_RE = re.compile(r"^\s*(eq|ge|gt|le|lt)\s*:\s*(.*)$")
_STRING_MATCH_RE = re.compile(
    r"^\s*-\s*(?:exact match|substring match|prefix match|suffix match|subdir match|domain match)\s*"
    r"\(-m\s+(\w+)\)\s*:\s*(.*)$",
    re.IGNORECASE,
)
_PREDEFINED_ACL_RE = re.compile(r"^([A-Z][A-Z0-9_]+)\s{2,}")


@dataclass
class AclReferenceDoc:
    flags: dict[str, str] = field(default_factory=dict)
    match_methods: dict[str, str] = field(default_factory=dict)
    int_operators: dict[str, str] = field(default_factory=dict)
    string_match_methods: dict[str, str] = field(default_factory=dict)
    predefined_acls: dict[str, str] = field(default_factory=dict)


def _section_range(
    lines: list[str], section_id: str, next_id: str | None
) -> tuple[int, int]:
    start = _find_body_section(lines, section_id)
    if start < 0:
        return -1, -1
    end = _find_body_section(lines, next_id) if next_id else len(lines)
    if end < 0:
        end = len(lines)
    return start, end


def _append_continued_description(mapping: dict[str, str], key: str | None, text: str) -> None:
    if not key or key not in mapping:
        return
    piece = text.strip()
    if not piece:
        return
    mapping[key] = f"{mapping[key]} {piece}" if mapping[key] else piece


def _parse_7_1_flags_and_methods(
    lines: list[str], start: int, end: int, out: AclReferenceDoc
) -> None:
    in_flags = False
    in_methods = False
    last_flag: str | None = None
    last_method: str | None = None
    for raw in lines[start:end]:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if "following ACL flags are currently supported" in stripped:
            in_flags = True
            in_methods = False
            last_flag = None
            last_method = None
            continue
        if "pattern matching method must be one of the following" in stripped:
            in_flags = False
            in_methods = True
            last_flag = None
            last_method = None
            continue
        if stripped.startswith("7.1.") and "ACL" not in stripped:
            break
        if not in_flags and not in_methods:
            continue
        if in_flags:
            m = _FLAG_RE.match(line)
            if m:
                last_flag = m.group(1)
                out.flags[last_flag] = stripped.split(":", 1)[-1].strip()
            elif last_flag and line.startswith(" ") and stripped:
                _append_continued_description(out.flags, last_flag, stripped)
        elif in_methods:
            m = _QUOTED_METHOD_RE.match(line)
            if m:
                last_method = m.group(1).lower()
                out.match_methods[last_method] = m.group(2).strip()
            elif last_method and line.startswith(" ") and stripped:
                _append_continued_description(out.match_methods, last_method, stripped)


def _parse_7_1_2_operators(
    lines: list[str], start: int, end: int, out: AclReferenceDoc
) -> None:
    in_ops = False
    for offset, raw in enumerate(lines[start:end]):
        line = raw.rstrip("\n")
        stripped = line.strip()
        if "Available operators for integer matching" in stripped:
            in_ops = True
            continue
        if offset > 2 and stripped.startswith("7.1.") and "Matching" in stripped:
            break
        if not in_ops:
            continue
        m = _INT_OP_RE.match(line)
        if m:
            out.int_operators[m.group(1).lower()] = m.group(2).strip()


def _parse_7_1_3_string_methods(
    lines: list[str], start: int, end: int, out: AclReferenceDoc
) -> None:
    for raw in lines[start:end]:
        line = raw.rstrip("\n")
        m = _STRING_MATCH_RE.match(line)
        if m:
            out.string_match_methods[m.group(1).lower()] = m.group(2).strip()


def _parse_7_4_predefined(
    lines: list[str], start: int, end: int, out: AclReferenceDoc
) -> None:
    in_table = False
    for raw in lines[start:end]:
        line = raw.rstrip("\n")
        if "ACL name" in line and "Equivalent to" in line:
            in_table = True
            continue
        if not in_table:
            continue
        if line.strip().startswith("---"):
            continue
        m = _PREDEFINED_ACL_RE.match(line)
        if m:
            name = m.group(1)
            rest = line[m.end() :].strip()
            if rest:
                out.predefined_acls[name] = rest


def parse_acl_reference(path: Path) -> AclReferenceDoc:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out = AclReferenceDoc()

    s71, e71 = _section_range(lines, "7.1", "7.1.1")
    if s71 >= 0:
        _parse_7_1_flags_and_methods(lines, s71, e71, out)

    s712, e712 = _section_range(lines, "7.1.2", "7.1.3")
    if s712 >= 0:
        _parse_7_1_2_operators(lines, s712, e712, out)

    s713, e713 = _section_range(lines, "7.1.3", "7.1.4")
    if s713 >= 0:
        _parse_7_1_3_string_methods(lines, s713, e713, out)

    s74, e74 = _section_range(lines, "7.4", "8")
    if s74 >= 0:
        _parse_7_4_predefined(lines, s74, e74, out)

    return out
