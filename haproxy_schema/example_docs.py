"""Extract Example:/Examples: blocks from configuration.txt (haproxy-dconv parity)."""

from __future__ import annotations

from dataclasses import dataclass
import re

EXAMPLE_HEADER_RE = re.compile(r"^ *(Examples? *:)(.*)")


def get_indent(line: str) -> int:
    indent = 0
    while indent < len(line) and line[indent] == " ":
        indent += 1
    return indent


@dataclass
class ExampleDoc:
    title: str = ""
    code: str = ""


def remove_indent(lines: list[str]) -> list[str]:
    """Strip common minimum leading whitespace from example lines."""
    min_indent = -1
    for line in lines:
        if not line.strip():
            continue
        indent = get_indent(line)
        if min_indent < 0 or indent < min_indent:
            min_indent = indent
    if min_indent > 0:
        return [line[min_indent:] if line.strip() else line for line in lines]
    return lines


def _line_at(lines: list[str], idx: int) -> str:
    if idx < 0 or idx >= len(lines):
        return ""
    return lines[idx].rstrip()


def _eat_empty_lines(lines: list[str], idx: int, end_idx: int) -> tuple[int, int]:
    count = 0
    while idx < end_idx and not _line_at(lines, idx).strip():
        count += 1
        idx += 1
    return idx, count


def extract_example_at(lines: list[str], idx: int, end_idx: int) -> tuple[ExampleDoc, int] | None:
    """Parse a single Example:/Examples: block starting at *idx*."""
    line = _line_at(lines, idx)
    result = EXAMPLE_HEADER_RE.search(line)
    if not result:
        return None

    title = result.group(2).strip()
    title_indent = len(line) - len(title) if title else 0
    header_indent = get_indent(line)

    if title:
        scan = idx + 1
        while scan < end_idx:
            next_line = _line_at(lines, scan)
            if not next_line.strip():
                break
            if get_indent(next_line) != title_indent:
                break
            title += " " + next_line.strip()
            scan += 1

    idx += 1
    idx, empty_after_header = _eat_empty_lines(lines, idx, end_idx)

    content: list[str] = []
    next_line = _line_at(lines, idx) if idx < end_idx else ""

    if idx < end_idx and get_indent(next_line) > header_indent:
        if title:
            title = title[0].upper() + title[1:]
        pending_empty = 0
        while idx < end_idx:
            current = _line_at(lines, idx)
            if current.strip() and get_indent(current) <= header_indent:
                break
            if not current.strip():
                pending_empty += 1
                idx += 1
                continue
            for _ in range(pending_empty):
                content.append("")
            content.append(current)
            pending_empty = 0
            idx += 1
    elif idx < end_idx and get_indent(next_line) == header_indent:
        if empty_after_header and title:
            content.append(" " * header_indent + title)
            title = ""
        else:
            while idx < end_idx and get_indent(_line_at(lines, idx)) >= header_indent:
                content.append(_line_at(lines, idx))
                idx += 1
            idx, _ = _eat_empty_lines(lines, idx, end_idx)

    if not content:
        return ExampleDoc(title=title, code=""), idx

    dedented = remove_indent(content)
    while dedented and not dedented[-1].strip():
        dedented.pop()
    code = "\n".join(dedented).rstrip()
    return ExampleDoc(title=title, code=code), idx


def extract_example_blocks(lines: list[str], start_idx: int, end_idx: int) -> list[ExampleDoc]:
    """Collect all Example:/Examples: blocks within a documentation section."""
    examples: list[ExampleDoc] = []
    idx = start_idx
    while idx < end_idx:
        if EXAMPLE_HEADER_RE.search(_line_at(lines, idx)):
            parsed, next_idx = extract_example_at(lines, idx, end_idx)
            if parsed is not None and parsed.code:
                examples.append(parsed)
            idx = max(next_idx, idx + 1)
            continue
        idx += 1
    return examples
