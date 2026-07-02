"""Parse bind/server line options from configuration.txt sections 5.1 and 5.2."""

from __future__ import annotations

import re

from .dconv_bridge import (
    KeywordDoc,
    _skip_arguments_block,
    collect_signature_lines,
    extract_contexts_from_keyword_block,
    extract_keyword_name,
    is_valid_keyword_name,
    match_dconv_keyword_line,
)
from .example_docs import extract_example_blocks

_CONTEXTS_RE = re.compile(r"^  May be used in the following contexts:", re.I)
_SECTIONS_HEADER_RE = re.compile(r"^  May be used in sections\s*:", re.I)
_ARGUMENTS_HEADER_RE = re.compile(r"^  Arguments?\s*:", re.I)
_EXAMPLE_HEADER_RE = re.compile(r"^  Examples?\s*:", re.I)
_SEE_ALSO_RE = re.compile(r"^  See also", re.I)
_SECTIONS_MATRIX_HEADER_RE = re.compile(
    r"^\s*(defaults|frontend|listen|backend)\s*(\|\s*(defaults|frontend|listen|backend)\s*)+$",
    re.I,
)
_SECTIONS_MATRIX_VALUE_RE = re.compile(
    r"^\s*(yes|no|-)\s*(\|\s*(yes|no|-)\s*)+$",
    re.I,
)


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
    stripped = line.strip()
    if _SECTIONS_MATRIX_HEADER_RE.match(stripped):
        return True
    if _SECTIONS_MATRIX_VALUE_RE.match(stripped):
        return True
    return False


def _is_structured_doc_line(line: str) -> bool:
    stripped = line.rstrip()
    if not stripped:
        return False
    return (
        "|" in stripped
        or re.match(r"^\s*[-+]{8,}\s*$", stripped) is not None
        or re.match(r"^\s*[-]{4,}\+[-+]{4,}\s*$", stripped) is not None
    )


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

    paragraphs: list[str] = []
    current: list[str] = []
    while idx < end_idx:
        line = lines[idx]
        if match_dconv_keyword_line(line):
            break
        if line.strip() and not line.startswith(" "):
            break
        if not line.strip():
            if current:
                paragraphs.append(" ".join(current).strip())
                current = []
            idx += 1
            continue
        if _EXAMPLE_HEADER_RE.match(line) or _SEE_ALSO_RE.match(line):
            break
        if _ARGUMENTS_HEADER_RE.match(line):
            idx = _skip_arguments_block(lines, idx, end_idx)
            continue
        if _is_metadata_line(line):
            if current:
                paragraphs.append(" ".join(current).strip())
                current = []
            idx = _skip_metadata_block(lines, idx, end_idx)
            continue
        if _is_structured_doc_line(line):
            if current:
                paragraphs.append(" ".join(current).strip())
                current = []
            structured: list[str] = []
            while idx < end_idx:
                structured_line = lines[idx]
                if not structured_line.strip():
                    break
                if _ARGUMENTS_HEADER_RE.match(structured_line) or _EXAMPLE_HEADER_RE.match(structured_line) or _SEE_ALSO_RE.match(structured_line):
                    break
                if match_dconv_keyword_line(structured_line):
                    break
                if structured_line.strip() and not structured_line.startswith(" "):
                    break
                if not _is_structured_doc_line(structured_line):
                    break
                structured.append(structured_line.rstrip())
                idx += 1
            if structured:
                paragraphs.append("\n".join(structured).strip())
            continue
        if line.startswith(" "):
            current.append(line.strip())
            idx += 1
            continue
        break

    if current:
        paragraphs.append(" ".join(current).strip())

    return "\n\n".join(paragraph for paragraph in paragraphs if paragraph).strip()


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
        example_docs = extract_example_blocks(lines, idx, block_end)
        contexts = extract_contexts_from_keyword_block(lines, idx, block_end)

        for sig in signatures:
            for name in _option_lookup_names(sig):
                entry = docs.get(name)
                if entry is None:
                    entry = KeywordDoc(name=name)
                    docs[name] = entry
                variant = entry.variant_for(chapter)
                if sig not in variant.signatures:
                    variant.signatures.append(sig)
                if description and not variant.description:
                    variant.description = description
                if example_docs and not variant.examples:
                    variant.examples = list(example_docs)
                for context in contexts:
                    if context not in variant.contexts:
                        variant.contexts.append(context)

        idx = max(next_idx, idx + 1)
    return docs
