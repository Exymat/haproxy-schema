"""Parse log-format alias and flag reference data from configuration.txt §8.2.6."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re


_TABLE_INTRO_RE = re.compile(
    r"Please refer to the table below for currently defined (?:variables|aliases)"
)
_TABLE_BORDER_RE = re.compile(r"^\s*\+[-=+]+\+")
_FLAGS_INTRO_RE = re.compile(r"^(Flags are|Supported item flags are)")
_FLAG_ITEM_RE = re.compile(r"^\s*\*\s+(\w+):\s+(.*)$")
_ALIAS_RE = re.compile(r"^%[A-Za-z][A-Za-z0-9]*$")
_LEGEND_RE = re.compile(r"^\s*R\s*=\s*Restrictions")


@dataclass
class LogformatAlias:
    name: str
    field_name: str = ""
    sample_fetch: str = ""
    type: str = ""
    restrictions: str = ""
    category: str = ""


@dataclass
class LogformatReferenceDoc:
    flags: dict[str, str] = field(default_factory=dict)
    aliases: dict[str, LogformatAlias] = field(default_factory=dict)


def _find_body_section(lines: list[str], section_id: str) -> int:
    pattern = re.compile(rf"^{re.escape(section_id)}(?!\d)\.\s+\S")
    for idx, line in enumerate(lines):
        if not pattern.match(line.strip()):
            continue
        for offset in range(1, 4):
            if idx + offset < len(lines) and set(lines[idx + offset].strip()) == {"-"}:
                return idx
    return -1


def _split_table_row(line: str) -> list[str]:
    parts = line.split("|")
    if parts and not parts[0].strip():
        parts = parts[1:]
    if parts and not parts[-1].strip():
        parts = parts[:-1]
    return [part.strip() for part in parts]


def _parse_flags(lines: list[str], start: int, end: int, out: LogformatReferenceDoc) -> None:
    in_flags = False
    current_flag: str | None = None
    for raw in lines[start:end]:
        stripped = raw.strip()
        if _FLAGS_INTRO_RE.match(stripped):
            in_flags = True
            continue
        if not in_flags:
            continue
        if stripped.startswith("Example:") or _TABLE_INTRO_RE.search(stripped):
            break
        match = _FLAG_ITEM_RE.match(raw)
        if match:
            current_flag = match.group(1)
            out.flags[current_flag] = match.group(2).strip()
            continue
        if current_flag and stripped and not stripped.startswith("*"):
            out.flags[current_flag] = f"{out.flags[current_flag]} {stripped}".strip()


@dataclass
class _PendingTableRow:
    restriction: str = ""
    alias: str = ""
    field_name: str = ""
    sample_fetch: str = ""
    type: str = ""


def _merge_physical_line(pending: _PendingTableRow, cols: list[str]) -> None:
    while len(cols) < 4:
        cols.append("")

    restriction, alias, field, alias_type = cols[0], cols[1], cols[2], cols[3]
    if restriction:
        pending.restriction = restriction
    if alias:
        pending.alias = alias
    if field:
        if field.startswith("%["):
            pending.sample_fetch = field
        elif not pending.field_name:
            pending.field_name = field
        else:
            pending.field_name = f"{pending.field_name} {field}".strip()
    if alias_type:
        pending.type = alias_type


def _parse_aliases_table(lines: list[str], start: int, end: int, out: LogformatReferenceDoc) -> None:
    table_start = -1
    for idx in range(start, end):
        if _TABLE_INTRO_RE.search(lines[idx]):
            table_start = idx
            break
    if table_start < 0:
        return

    pending: _PendingTableRow | None = None
    category = ""

    for raw in lines[table_start:end]:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if _LEGEND_RE.match(stripped):
            break
        if not stripped:
            continue
        if not _TABLE_BORDER_RE.match(line) and "|" not in line:
            continue

        if _TABLE_BORDER_RE.match(line):
            if pending:
                category = _commit_table_row(pending, category, out)
                pending = None
            continue

        cols = _split_table_row(line)
        if not cols:
            continue
        if cols[0].lower() in {"r", "alias", "var"} or "sample fetch" in " ".join(cols).lower():
            continue

        if pending is None:
            pending = _PendingTableRow()
        _merge_physical_line(pending, cols)

    if pending:
        _commit_table_row(pending, category, out)


def _commit_table_row(
    row: _PendingTableRow,
    category: str,
    out: LogformatReferenceDoc,
) -> str:
    alias = row.alias
    field = row.field_name

    if alias and _ALIAS_RE.match(alias):
        out.aliases[alias] = LogformatAlias(
            name=alias,
            field_name=field,
            sample_fetch=row.sample_fetch,
            type=row.type,
            restrictions=row.restriction,
            category=category,
        )
        return category

    if not alias and not row.restriction and field and not field.startswith("%"):
        lowered = field.lower()
        if "formats" in lowered or lowered in {"others", "timing events"}:
            return field.strip()

    return category


def parse_logformat_reference(path: Path) -> LogformatReferenceDoc:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out = LogformatReferenceDoc()

    section_start = _find_body_section(lines, "8.2.6")
    if section_start < 0:
        return out

    section_end = _find_body_section(lines, "8.3")
    if section_end < 0:
        section_end = len(lines)

    _parse_flags(lines, section_start, section_end, out)
    _parse_aliases_table(lines, section_start, section_end, out)
    return out
