from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re

from .dconv_bridge import KeywordDoc, merge_argument_docs, walk_keyword_docs

SECTIONS_MATRIX = ["defaults", "frontend", "listen", "backend"]


@dataclass
class DocParseResult:
    global_keywords: set[str] = field(default_factory=set)
    matrix_keywords: dict[str, set[str]] = field(
        default_factory=lambda: {name: set() for name in SECTIONS_MATRIX}
    )
    signatures: dict[str, list[str]] = field(default_factory=dict)
    keyword_docs: dict[str, KeywordDoc] = field(default_factory=dict)


def _next_nonblank(lines: list[str], start: int) -> str:
    for idx in range(start, len(lines)):
        if lines[idx].strip():
            return lines[idx]
    return ""


def _find_body_section(lines: list[str], section_id: str) -> int:
    """Locate a documentation body section, not a summary-table-of-contents entry."""
    pattern = re.compile(rf"^{re.escape(section_id)}(?!\d)\.\s+\S")
    for idx, line in enumerate(lines):
        if not pattern.match(line.strip()):
            continue
        underline = _next_nonblank(lines, idx + 1)
        if underline and set(underline.strip()) == {"-"}:
            return idx
    return -1


def _extract_4_1_matrix(lines: list[str], start_idx: int, end_idx: int) -> dict[str, set[str]]:
    out = {name: set() for name in SECTIONS_MATRIX}
    for raw_line in lines[start_idx:end_idx]:
        line = raw_line.rstrip("\n")
        if not line.strip():
            continue
        if line.lstrip().startswith("-- keyword"):
            continue
        if "defaults" in line and "frontend" in line and "listen" in line and "backend" in line:
            continue
        if line.strip().startswith("-"):
            continue

        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) < 5:
            continue

        keyword = parts[0].strip()
        if not keyword:
            continue
        keyword = re.sub(r"\s+\(\*\)$", "", keyword).strip()
        keyword = re.sub(r"\s+\(deprecated\)$", "", keyword).strip()
        if keyword.startswith("-- "):
            continue

        cols_start = 1
        if len(parts) > 5 and parts[1].strip() in {"(*)", "(!)"}:
            cols_start = 2
        cols = parts[cols_start : cols_start + 4]
        if len(cols) < 4:
            continue
        for section, col in zip(SECTIONS_MATRIX, cols):
            if "X" in col:
                out[section].add(keyword)
    return out


def _merge_keyword_docs(
    target: dict[str, KeywordDoc],
    source: dict[str, KeywordDoc],
    *,
    prefer_source_description: bool = False,
) -> None:
    for name, doc in source.items():
        entry = target.get(name)
        if entry is None:
            target[name] = KeywordDoc(
                name=doc.name,
                signatures=list(doc.signatures),
                description=doc.description,
                chapter=doc.chapter,
                arguments=list(doc.arguments),
            )
            continue
        for sig in doc.signatures:
            if sig not in entry.signatures:
                entry.signatures.append(sig)
        if doc.description:
            if prefer_source_description or not entry.description:
                entry.description = doc.description
        if doc.chapter and (prefer_source_description or not entry.chapter):
            entry.chapter = doc.chapter
        if doc.arguments:
            merge_argument_docs(entry, doc.arguments)


def _sections_for_keyword(matrix: dict[str, set[str]], name: str) -> list[str]:
    return [section for section in SECTIONS_MATRIX if name in matrix.get(section, set())]


def _sections_for_doc(
    name: str,
    global_keywords: set[str],
    matrix: dict[str, set[str]],
) -> list[str]:
    sections: list[str] = []
    if name in global_keywords:
        sections.append("global")
    for section in _sections_for_keyword(matrix, name):
        if section not in sections:
            sections.append(section)
    return sections


def parse_configuration(path: Path) -> DocParseResult:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    section_31 = _find_body_section(lines, "3.1")
    section_34 = _find_body_section(lines, "3.4")
    section_41 = _find_body_section(lines, "4.1")
    section_42 = _find_body_section(lines, "4.2")
    section_43 = _find_body_section(lines, "4.3")
    if section_43 < 0:
        section_43 = len(lines)

    if section_31 < 0 or section_34 < 0 or section_41 < 0 or section_42 < 0:
        raise ValueError("Failed to locate required sections 3.1/3.4/4.1/4.2 in configuration.txt")

    result = DocParseResult()

    result.matrix_keywords = _extract_4_1_matrix(lines, section_41, section_42)

    # Only 3.1–3.3 directives belong in the HAProxy "global" section (not peers, userlists, etc.).
    global_docs = walk_keyword_docs(lines, section_31, section_34, "3.1")
    other_chapter3_docs = walk_keyword_docs(lines, section_34, section_41, "3.4")
    proxy_docs = walk_keyword_docs(lines, section_42, section_43, "4.2")
    _merge_keyword_docs(result.keyword_docs, global_docs)
    _merge_keyword_docs(result.keyword_docs, other_chapter3_docs)
    _merge_keyword_docs(result.keyword_docs, proxy_docs, prefer_source_description=True)

    result.global_keywords = set(global_docs.keys())
    known = set(result.global_keywords)
    for keywords in result.matrix_keywords.values():
        known.update(keywords)

    for name, doc in result.keyword_docs.items():
        result.signatures[name] = list(doc.signatures)
        doc.sections = _sections_for_doc(name, result.global_keywords, result.matrix_keywords)
        if not doc.sections and " " in name:
            doc.sections = _sections_for_doc(
                name.split()[0], result.global_keywords, result.matrix_keywords
            )
        if _sections_for_keyword(result.matrix_keywords, name) or (
            " " in name
            and _sections_for_keyword(result.matrix_keywords, name.split()[0])
        ):
            doc.chapter = "4.2"

    for name in known:
        if name not in result.keyword_docs:
            matrix_sections = _sections_for_keyword(result.matrix_keywords, name)
            result.keyword_docs[name] = KeywordDoc(
                name=name,
                signatures=[name],
                sections=_sections_for_doc(name, result.global_keywords, result.matrix_keywords),
                chapter="4.2" if matrix_sections else "3.1",
            )
            result.signatures.setdefault(name, [name])

    return result
