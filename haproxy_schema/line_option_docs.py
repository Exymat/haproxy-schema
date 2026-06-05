"""Parse bind/server line options from configuration.txt sections 5.1 and 5.2."""

from __future__ import annotations

import re

from .dconv_bridge import (
    KeywordDoc,
    collect_signature_lines,
    extract_contexts_from_keyword_block,
    extract_keyword_name,
    is_valid_keyword_name,
    match_dconv_keyword_line,
)

_CONTEXTS_RE = re.compile(r"^  May be used in the following contexts:", re.I)
_SECTIONS_HEADER_RE = re.compile(r"^  May be used in sections\s*:", re.I)
_ARGUMENTS_HEADER_RE = re.compile(r"^  Arguments?\s*:", re.I)
_EXAMPLE_HEADER_RE = re.compile(r"^  Examples?\s*:", re.I)
_SEE_ALSO_RE = re.compile(r"^  See also", re.I)
_MATRIX_ROW_RE = re.compile(r"^\s+.+(\||\s+yes\s+|\s+no\s+)", re.I)


def _is_metadata_line(line: str) -> bool:
    if not line.strip():
        return True
    if _CONTEXTS_RE.match(line):
        return True
    if _SECTIONS_HEADER_RE.match(line):
        return True
    if "May be used in the following contexts" in line:
        return True
    if "May be used in sections" in line:
        return True
    if _MATRIX_ROW_RE.match(line) and "|" in line:
        return True
    return False


def _skip_metadata_block(lines: list[str], idx: int, end_idx: int) -> int:
    while idx < end_idx:
        line = lines[idx]
        if not line.strip():
            idx += 1
            continue
        if _ARGUMENTS_HEADER_RE.match(line) or _EXAMPLE_HEADER_RE.match(line) or _SEE_ALSO_RE.match(line):
            return idx
        if match_dconv_keyword_line(line):
            return idx
        if line.strip() and not line.startswith(" "):
            return idx
        if _is_metadata_line(line):
            idx += 1
            continue
        break
    return idx


def extract_line_option_description(lines: list[str], header_idx: int, end_idx: int) -> str:
    """Extract prose description from a 5.1/5.2 line-option block."""
    _, next_idx = collect_signature_lines(lines, header_idx)
    idx = _skip_metadata_block(lines, next_idx, end_idx)

    parts: list[str] = []
    while idx < end_idx:
        line = lines[idx]
        if match_dconv_keyword_line(line):
            break
        if line.strip() and not line.startswith(" "):
            break
        if not line.strip():
            if parts:
                break
            idx += 1
            continue
        if _ARGUMENTS_HEADER_RE.match(line) or _EXAMPLE_HEADER_RE.match(line) or _SEE_ALSO_RE.match(line):
            break
        if _is_metadata_line(line):
            idx = _skip_metadata_block(lines, idx, end_idx)
            continue
        if line.startswith(" "):
            parts.append(line.strip())
            idx += 1
            continue
        break

    return " ".join(parts).strip()


def _keyword_block_end(lines: list[str], header_idx: int, end_idx: int) -> int:
    signatures, next_idx = collect_signature_lines(lines, header_idx)
    idx = next_idx
    while idx < end_idx:
        if match_dconv_keyword_line(lines[idx]):
            return idx
        if lines[idx].strip() and not lines[idx].startswith(" "):
            return idx
        idx += 1
    return end_idx


def _option_lookup_names(signature: str) -> list[str]:
    name = extract_keyword_name(signature)
    if not name or not is_valid_keyword_name(name):
        return []
    names = [name]
    parts = name.split()
    if len(parts) > 1 and parts[0] not in names:
        names.append(parts[0])
    return names


def walk_line_option_docs(
    lines: list[str],
    start_idx: int,
    end_idx: int,
    chapter: str,
) -> dict[str, KeywordDoc]:
    docs: dict[str, KeywordDoc] = {}
    idx = start_idx
    while idx < end_idx:
        matched = match_dconv_keyword_line(lines[idx])
        if not matched:
            idx += 1
            continue

        signatures, next_idx = collect_signature_lines(lines, idx)
        block_end = min(_keyword_block_end(lines, idx, end_idx), end_idx)
        description = extract_line_option_description(lines, idx, block_end)
        contexts = extract_contexts_from_keyword_block(lines, idx, block_end)

        for sig in signatures:
            for name in _option_lookup_names(sig):
                entry = docs.get(name)
                if entry is None:
                    entry = KeywordDoc(name=name, chapter=chapter)
                    docs[name] = entry
                if sig not in entry.signatures:
                    entry.signatures.append(sig)
                if description and not entry.description:
                    entry.description = description
                for context in contexts:
                    if context not in entry.contexts:
                        entry.contexts.append(context)

        idx = max(next_idx, idx + 1)
    return docs
