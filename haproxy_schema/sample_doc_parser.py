from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re

from .dconv_bridge import extract_keyword_name, match_dconv_keyword_line


@dataclass
class SampleDoc:
    name: str
    signature: str = ""
    description: str = ""
    chapter: str = ""
    input_type: str = ""
    output_type: str = ""
    deprecated: bool = False


@dataclass
class SampleReferenceDoc:
    fetches: dict[str, SampleDoc] = field(default_factory=dict)
    converters: dict[str, SampleDoc] = field(default_factory=dict)


def _find_body_section(lines: list[str], section_id: str) -> int:
    pattern = re.compile(rf"^{re.escape(section_id)}(?!\d)\.\s+\S")
    for idx, line in enumerate(lines):
        if not pattern.match(line.strip()):
            continue
        for offset in range(1, 5):
            if idx + offset >= len(lines):
                break
            stripped = lines[idx + offset].strip()
            if not stripped:
                continue
            if set(stripped) == {"-"}:
                return idx
            break
    return -1


def _section_range(lines: list[str], section_id: str, next_id: str | None) -> tuple[int, int]:
    start = _find_body_section(lines, section_id)
    if start < 0:
        return -1, -1
    end = _find_body_section(lines, next_id) if next_id else len(lines)
    if end < 0:
        end = len(lines)
    return start, end


def _sample_name(signature: str) -> str:
    return extract_keyword_name(signature)


def _summary_entries(lines: list[str], start: int, end: int, *, converters: bool) -> dict[str, SampleDoc]:
    entries: dict[str, SampleDoc] = {}
    in_table = False
    for raw in lines[start:end]:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith("detailed list"):
            break
        if stripped.lower().startswith("keyword") and "type" in stripped.lower():
            in_table = True
            continue
        if not in_table:
            continue
        if set(stripped.replace("+", "")) <= {"-", "|"}:
            continue
        parts = re.split(r"\s{2,}", stripped)
        if converters:
            if len(parts) < 3:
                continue
            signature, input_type, output_type = parts[0].strip(), parts[1].strip(), parts[2].strip()
            if signature.startswith("-- "):
                continue
            name = _sample_name(signature)
            if not name:
                continue
            entries[name] = SampleDoc(
                name=name,
                signature=signature,
                chapter="7.3.1",
                input_type=input_type,
                output_type=output_type,
            )
        else:
            if len(parts) < 2:
                continue
            signature, output_type = parts[0].strip(), parts[1].strip()
            if signature.startswith("-- "):
                continue
            name = _sample_name(signature)
            if not name:
                continue
            entries[name] = SampleDoc(
                name=name,
                signature=signature,
                output_type=output_type,
            )
    return entries


def _find_detailed_list_start(lines: list[str], start: int, end: int, *, converters: bool) -> int:
    for idx in range(start, end):
        if lines[idx].strip().lower().startswith("detailed list"):
            return idx + 1
    if converters:
        in_table = False
        for idx in range(start, end):
            stripped = lines[idx].strip()
            if stripped.lower().startswith("keyword") and "type" in stripped.lower():
                in_table = True
                continue
            if not in_table:
                continue
            if not stripped:
                continue
            if set(stripped.replace("+", "")) <= {"-", "|"}:
                continue
            parts = re.split(r"\s{2,}", stripped)
            if len(parts) >= 3:
                continue
            return idx
    return -1


def _detailed_header_signature(line: str, *, converters: bool) -> tuple[str, bool] | None:
    stripped = line.strip()
    if not stripped or line.startswith(" "):
        return None
    if converters:
        matched = match_dconv_keyword_line(line)
        if not matched:
            return None
        signature = matched[1]
        deprecated = signature.lower().endswith("(deprecated)")
        signature = re.sub(r"\s+\(deprecated\)$", "", signature, flags=re.IGNORECASE)
        return signature, deprecated
    match = re.match(r"^(.+?)\s*:\s*([a-zA-Z0-9_+ /-]+)(?:\s+\(deprecated\))?$", stripped)
    if not match:
        return None
    deprecated = bool(re.search(r"\s+\(deprecated\)$", stripped, flags=re.IGNORECASE))
    return match.group(1).strip(), deprecated


def _extract_first_paragraph(lines: list[str], start: int, end: int) -> str:
    parts: list[str] = []
    idx = start
    while idx < end:
        line = lines[idx]
        stripped = line.strip()
        if not stripped:
            if parts:
                break
            idx += 1
            continue
        if not line.startswith("  "):
            break
        if stripped.startswith(("ACL derivatives", "Example", "Examples", "See also", "Note:")):
            break
        parts.append(stripped)
        idx += 1
    return " ".join(parts).strip()


def _merge_details(
    lines: list[str],
    start: int,
    end: int,
    entries: dict[str, SampleDoc],
    *,
    converters: bool,
    chapter: str,
) -> None:
    detail_start = _find_detailed_list_start(lines, start, end, converters=converters)
    if detail_start < 0:
        detail_start = start
    idx = detail_start
    while idx < end:
        header_info = _detailed_header_signature(lines[idx], converters=converters)
        if not header_info:
            idx += 1
            continue
        header_chain: list[tuple[str, bool]] = [header_info]
        scan = idx + 1
        while scan < end:
            next_header = _detailed_header_signature(lines[scan], converters=converters)
            if not next_header:
                break
            header_chain.append(next_header)
            scan += 1

        block_end = scan
        while block_end < end:
            if _detailed_header_signature(lines[block_end], converters=converters):
                break
            if lines[block_end].strip().startswith("7.3."):
                break
            block_end += 1
        description = _extract_first_paragraph(lines, scan, block_end)
        for header, deprecated in header_chain:
            name = _sample_name(header)
            if not name:
                continue
            entry = entries.get(name)
            if entry is None:
                entry = SampleDoc(name=name, signature=header, chapter=chapter)
                entries[name] = entry
            if not entry.signature:
                entry.signature = header
            if not entry.chapter:
                entry.chapter = chapter
            if deprecated:
                entry.deprecated = True
                if "(deprecated)" not in entry.signature.lower():
                    entry.signature = f"{entry.signature} (deprecated)"
            if description and not entry.description:
                entry.description = description
        idx = block_end


def _fill_missing_descriptions(
    lines: list[str],
    start: int,
    end: int,
    entries: dict[str, SampleDoc],
    *,
    converters: bool,
) -> None:
    detail_start = _find_detailed_list_start(lines, start, end, converters=converters)
    if detail_start < 0:
        detail_start = start
    for item in entries.values():
        if item.description:
            continue
        idx = detail_start
        while idx < end:
            header_info = _detailed_header_signature(lines[idx], converters=converters)
            if not header_info:
                idx += 1
                continue
            header, deprecated = header_info
            if _sample_name(header) != item.name:
                idx += 1
                continue
            if deprecated:
                item.deprecated = True
                if item.signature and "(deprecated)" not in item.signature.lower():
                    item.signature = f"{item.signature} (deprecated)"
            block_end = idx + 1
            while block_end < end:
                if _detailed_header_signature(lines[block_end], converters=converters):
                    break
                if lines[block_end].strip().startswith("7.3."):
                    break
                block_end += 1
            description = _extract_first_paragraph(lines, idx + 1, block_end)
            if description:
                item.description = description
            break


def parse_sample_reference(path: Path) -> SampleReferenceDoc:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out = SampleReferenceDoc()

    s731, e731 = _section_range(lines, "7.3.1", "7.3.2")
    if s731 >= 0:
        out.converters = _summary_entries(lines, s731, e731, converters=True)
        _merge_details(lines, s731, e731, out.converters, converters=True, chapter="7.3.1")
        _fill_missing_descriptions(lines, s731, e731, out.converters, converters=True)

    fetch_sections = [
        ("7.3.2", "7.3.3"),
        ("7.3.3", "7.3.4"),
        ("7.3.4", "7.3.5"),
        ("7.3.5", "7.3.6"),
        ("7.3.6", "7.3.7"),
        ("7.3.7", "7.4"),
    ]
    for section_id, next_id in fetch_sections:
        start, end = _section_range(lines, section_id, next_id)
        if start < 0:
            continue
        parsed = _summary_entries(lines, start, end, converters=False)
        for name, item in parsed.items():
            existing = out.fetches.get(name)
            if existing is None:
                item.chapter = section_id
                out.fetches[name] = item
            else:
                if not existing.signature:
                    existing.signature = item.signature
                if not existing.output_type:
                    existing.output_type = item.output_type
                if not existing.chapter:
                    existing.chapter = section_id
        _merge_details(lines, start, end, out.fetches, converters=False, chapter=section_id)
        _fill_missing_descriptions(lines, start, end, out.fetches, converters=False)

    return out
