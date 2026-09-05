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


def _is_hanging_wrap(line: str) -> bool:
    """True for indented wrap lines that continue the current bullet/item."""
    return bool(line.strip()) and line[:1].isspace()


def _append_wrap(store: dict[str, str], key: str | None, line: str) -> str | None:
    if key is None or not _is_hanging_wrap(line):
        return None
    store[key] = f"{store[key]} {line.strip()}".strip()
    return key


def _parse_7_1_flags_and_methods(
    lines: list[str], start: int, end: int, out: AclReferenceDoc
) -> None:
    in_flags = False
    in_methods = False
    last_key: str | None = None
    for raw in lines[start:end]:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if "following ACL flags are currently supported" in stripped:
            in_flags = True
            in_methods = False
            last_key = None
            continue
        if "pattern matching method must be one of the following" in stripped:
            in_flags = False
            in_methods = True
            last_key = None
            continue
        if stripped.startswith("7.1.") and "ACL" not in stripped:
            break
        if not in_flags and not in_methods:
            continue
        if in_flags:
            m = _FLAG_RE.match(line)
            if m:
                last_key = m.group(1)
                out.flags[last_key] = stripped.split(":", 1)[-1].strip()
            else:
                last_key = _append_wrap(out.flags, last_key, line)
        elif in_methods:
            m = _QUOTED_METHOD_RE.match(line)
            if m:
                last_key = m.group(1).lower()
                out.match_methods[last_key] = m.group(2).strip()
            else:
                last_key = _append_wrap(out.match_methods, last_key, line)


def _parse_7_1_2_operators(
    lines: list[str], start: int, end: int, out: AclReferenceDoc
) -> None:
    in_ops = False
    last_key: str | None = None
    for offset, raw in enumerate(lines[start:end]):
        line = raw.rstrip("\n")
        stripped = line.strip()
        if "Available operators for integer matching" in stripped:
            in_ops = True
            last_key = None
            continue
        if offset > 2 and stripped.startswith("7.1.") and "Matching" in stripped:
            break
        if not in_ops:
            continue
        m = _INT_OP_RE.match(line)
        if m:
            last_key = m.group(1).lower()
            out.int_operators[last_key] = m.group(2).strip()
        else:
            last_key = _append_wrap(out.int_operators, last_key, line)


def _parse_7_1_3_string_methods(
    lines: list[str], start: int, end: int, out: AclReferenceDoc
) -> None:
    last_key: str | None = None
    for raw in lines[start:end]:
        line = raw.rstrip("\n")
        m = _STRING_MATCH_RE.match(line)
        if m:
            last_key = m.group(1).lower()
            out.string_match_methods[last_key] = m.group(2).strip()
        else:
            last_key = _append_wrap(out.string_match_methods, last_key, line)


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
