from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re

from .acl_doc_parser import AclReferenceDoc, parse_acl_reference
from .action_parser import (
    ActionDoc,
    action_matrix_from_reference,
    merge_action_matrices,
    parse_actions_lines,
)
from .dconv_bridge import KeywordDoc, is_valid_keyword_name, merge_argument_docs, walk_keyword_docs

SECTIONS_MATRIX = ["defaults", "frontend", "listen", "backend"]

# Section 4.3 matrix columns (after keyword) -> schema keyword_groups key.
_ACTION_MATRIX_COLS: tuple[tuple[str, int], ...] = (
    ("quic_initial_actions", 0),
    ("tcp_request_actions", 1),
    ("tcp_request_actions", 2),
    ("tcp_request_actions", 3),
    ("tcp_response_actions", 4),
    ("http_request_actions", 5),
    ("http_response_actions", 6),
    ("http_after_response_actions", 7),
)

ACTION_MATRIX_GROUP_KEYS = tuple(
    dict.fromkeys(group for group, _ in _ACTION_MATRIX_COLS)
)

# configuration.txt subsections whose keywords apply inside a named config section
# (not covered by the proxy keywords matrix in 4.1).
STANDALONE_SECTION_SPECS: tuple[tuple[str, str], ...] = (
    ("5.3.2", "resolvers"),
    ("6.2.1", "cache"),
    ("10.1.1", "fcgi-app"),
    ("11.2", "peers"),
    ("12.1", "traces"),
    ("12.2", "userlist"),
    ("12.3", "mailers"),
    ("12.4", "http-errors"),
    ("12.5", "ring"),
    ("12.7", "crt-store"),
    ("12.8", "acme"),
    ("12.9", "program"),
)

# Keywords that declare the section itself rather than an inner directive.
_SECTION_DECLARATION_KEYWORDS = frozenset(
    {
        "cache",
        "resolvers",
        "peers",
        "ring",
        "fcgi-app",
        "crt-store",
        "crt-list",
        "traces",
        "userlist",
        "mailers",
        "program",
        "acme",
    }
)


@dataclass
class DocParseResult:
    global_keywords: set[str] = field(default_factory=set)
    proxy_keywords: set[str] = field(default_factory=set)
    matrix_keywords: dict[str, set[str]] = field(
        default_factory=lambda: {name: set() for name in SECTIONS_MATRIX}
    )
    section_keywords: dict[str, set[str]] = field(default_factory=dict)
    action_matrix: dict[str, set[str]] = field(
        default_factory=lambda: {name: set() for name in ACTION_MATRIX_GROUP_KEYS}
    )
    action_reference: dict[str, ActionDoc] = field(default_factory=dict)
    no_prefix_keywords: set[str] = field(default_factory=set)
    signatures: dict[str, list[str]] = field(default_factory=dict)
    keyword_docs: dict[str, KeywordDoc] = field(default_factory=dict)
    acl_reference: AclReferenceDoc = field(default_factory=AclReferenceDoc)


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


def _find_subsection_end(lines: list[str], section_id: str, start_idx: int) -> int:
    """End index for a doc subsection: next body heading that is not a child of section_id."""
    header_re = re.compile(r"^(\d+(?:\.\d+)*)\.\s+\S")
    idx = start_idx + 1
    while idx < len(lines):
        stripped = lines[idx].strip()
        match = header_re.match(stripped)
        if match:
            other_id = match.group(1)
            underline = _next_nonblank(lines, idx + 1)
            if underline and set(underline.strip()) == {"-"}:
                if other_id != section_id and not other_id.startswith(f"{section_id}."):
                    return idx
        idx += 1
    return len(lines)


def _extract_4_1_matrix(lines: list[str], start_idx: int, end_idx: int) -> tuple[dict[str, set[str]], set[str]]:
    out = {name: set() for name in SECTIONS_MATRIX}
    no_prefix: set[str] = set()
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
        marker = parts[1].strip() if len(parts) > 1 else ""
        if marker == "(*)":
            no_prefix.add(keyword)
            cols_start = 2
        elif marker == "(!)":
            cols_start = 2
        cols = parts[cols_start : cols_start + 4]
        if len(cols) < 4:
            continue
        for section, col in zip(SECTIONS_MATRIX, cols):
            if "X" in col:
                out[section].add(keyword)
    return out, no_prefix


def _normalize_matrix_keyword(keyword: str) -> str:
    keyword = keyword.strip()
    keyword = re.sub(r"\s+\(\*\)$", "", keyword)
    keyword = re.sub(r"\s+\(deprecated\)$", "", keyword, flags=re.IGNORECASE)
    return keyword.strip()


def _extract_4_3_actions_matrix(lines: list[str], start_idx: int, end_idx: int) -> dict[str, set[str]]:
    """Parse section 4.3 (Actions keywords matrix) into keyword_groups buckets."""
    out: dict[str, set[str]] = {name: set() for name in ACTION_MATRIX_GROUP_KEYS}
    for raw_line in lines[start_idx:end_idx]:
        line = raw_line.rstrip("\n")
        if not line.strip():
            continue
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith("--keyword") or lower.startswith("-- keyword"):
            continue
        if "quic" in lower and "http:" in lower and "req" in lower and "keyword" in lower:
            continue
        if stripped.startswith("-") and set(stripped.replace("+", "")) <= {"-"}:
            continue

        parts = re.split(r"\s{2,}", stripped)
        if len(parts) < 2:
            continue

        keyword = _normalize_matrix_keyword(parts[0])
        if not keyword or not re.match(r"^[a-z]", keyword):
            continue

        marks = parts[1:]
        while len(marks) < 8:
            marks.append("-")
        for group, col_idx in _ACTION_MATRIX_COLS:
            if col_idx < len(marks) and "X" in marks[col_idx]:
                out[group].add(keyword)
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
                sections=list(doc.sections),
                arguments=list(doc.arguments),
            )
            continue
        for section in doc.sections:
            if section not in entry.sections:
                entry.sections.append(section)
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


def _matrix_from_proxy_docs(keyword_docs: dict[str, KeywordDoc]) -> dict[str, set[str]]:
    """Build section applicability from 4.2 keyword blocks (authoritative for proxy keywords)."""
    out = {name: set() for name in SECTIONS_MATRIX}
    for kw_name, doc in keyword_docs.items():
        if not is_valid_keyword_name(kw_name):
            continue
        for section in doc.sections:
            if section in out:
                out[section].add(kw_name)
    return out


def _filter_keyword_docs(docs: dict[str, KeywordDoc]) -> dict[str, KeywordDoc]:
    return {name: doc for name, doc in docs.items() if is_valid_keyword_name(name)}


def _is_standalone_directive(name: str) -> bool:
    """Keywords allowed inside named sections (cache, peers, …), not converter/filter catalogs."""
    if not is_valid_keyword_name(name):
        return False
    lowered = name.lower()
    if lowered.startswith("filter "):
        return False
    if " " in name:
        first = name.split()[0]
        if "." in first or first in {"req", "res", "srv", "be"}:
            return False
    return True


def _parse_standalone_sections(
    lines: list[str],
) -> tuple[dict[str, set[str]], dict[str, KeywordDoc]]:
    """Extract keywords documented for non-proxy sections (cache, peers, …)."""
    from .dconv_bridge import walk_keyword_docs

    section_keywords: dict[str, set[str]] = {}
    merged_docs: dict[str, KeywordDoc] = {}

    for section_id, config_section in STANDALONE_SECTION_SPECS:
        start = _find_body_section(lines, section_id)
        if start < 0:
            continue
        end = _find_subsection_end(lines, section_id, start)
        docs = walk_keyword_docs(lines, start, end, section_id)
        inner = {
            name: doc
            for name, doc in docs.items()
            if name not in _SECTION_DECLARATION_KEYWORDS and _is_standalone_directive(name)
        }
        if inner:
            bucket = section_keywords.setdefault(config_section, set())
            bucket.update(inner.keys())
            _merge_keyword_docs(merged_docs, inner)
            for doc in inner.values():
                if config_section not in doc.sections:
                    doc.sections.append(config_section)

    # Load options documented in 12.7.1 also apply inside crt-list sections.
    crt_list_start = _find_body_section(lines, "12.7.1")
    if crt_list_start >= 0:
        crt_list_end = _find_body_section(lines, "12.8")
        if crt_list_end < 0:
            crt_list_end = len(lines)
        load_docs = walk_keyword_docs(lines, crt_list_start, crt_list_end, "12.7.1")
        load_docs = {
            name: doc
            for name, doc in load_docs.items()
            if name not in _SECTION_DECLARATION_KEYWORDS and _is_standalone_directive(name)
        }
        if load_docs:
            bucket = section_keywords.setdefault("crt-list", set())
            bucket.update(load_docs.keys())
            _merge_keyword_docs(merged_docs, load_docs)
            for doc in load_docs.values():
                if "crt-list" not in doc.sections:
                    doc.sections.append("crt-list")

    return section_keywords, merged_docs


def _sections_for_doc(
    name: str,
    global_keywords: set[str],
    matrix: dict[str, set[str]],
    section_keywords: dict[str, set[str]] | None = None,
    doc_sections: list[str] | None = None,
) -> list[str]:
    sections: list[str] = []
    if name in global_keywords:
        sections.append("global")
    for section in _sections_for_keyword(matrix, name):
        if section not in sections:
            sections.append(section)
    if section_keywords:
        for section, keywords in section_keywords.items():
            if name in keywords and section not in sections:
                sections.append(section)
    for section in doc_sections or []:
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
    section_44 = _find_body_section(lines, "4.4")
    if section_43 < 0:
        section_43 = len(lines)
    if section_44 < 0:
        section_44 = len(lines)

    if section_31 < 0 or section_34 < 0 or section_41 < 0 or section_42 < 0:
        raise ValueError("Failed to locate required sections 3.1/3.4/4.1/4.2 in configuration.txt")

    result = DocParseResult()

    matrix_41, result.no_prefix_keywords = _extract_4_1_matrix(lines, section_41, section_42)
    matrix_43 = (
        _extract_4_3_actions_matrix(lines, section_43, section_44)
        if section_43 < section_44
        else {name: set() for name in ACTION_MATRIX_GROUP_KEYS}
    )

    # Only 3.1–3.3 directives belong in the HAProxy "global" section (not peers, userlists, etc.).
    global_docs = _filter_keyword_docs(walk_keyword_docs(lines, section_31, section_34, "3.1"))
    other_chapter3_docs = _filter_keyword_docs(walk_keyword_docs(lines, section_34, section_41, "3.4"))
    proxy_docs = _filter_keyword_docs(walk_keyword_docs(lines, section_42, section_43, "4.2"))
    result.proxy_keywords = set(proxy_docs.keys())
    _merge_keyword_docs(result.keyword_docs, global_docs)
    _merge_keyword_docs(result.keyword_docs, other_chapter3_docs)
    _merge_keyword_docs(result.keyword_docs, proxy_docs, prefer_source_description=True)

    result.section_keywords, standalone_docs = _parse_standalone_sections(lines)
    standalone_docs = _filter_keyword_docs(standalone_docs)
    _merge_keyword_docs(result.keyword_docs, standalone_docs)

    result.global_keywords = set(global_docs.keys())

    for name, doc in result.keyword_docs.items():
        if name in result.proxy_keywords:
            doc.chapter = "4.2"
        result.signatures[name] = list(doc.signatures)
        doc.sections = _sections_for_doc(
            name,
            result.global_keywords,
            matrix_41,
            result.section_keywords,
            doc_sections=doc.sections,
        )
        if not doc.sections and " " in name and name in result.proxy_keywords:
            prefix = name.split()[0]
            sibling_sections: list[str] = []
            for sibling_name, sibling_doc in result.keyword_docs.items():
                if sibling_name.startswith(f"{prefix} ") and sibling_doc.sections:
                    sibling_sections = list(sibling_doc.sections)
                    break
            if sibling_sections:
                doc.sections = _sections_for_doc(
                    name,
                    result.global_keywords,
                    matrix_41,
                    result.section_keywords,
                    doc_sections=sibling_sections,
                )

    # Section 4.2 is authoritative for proxy keyword inventory and section applicability.
    result.matrix_keywords = _matrix_from_proxy_docs(
        {name: doc for name, doc in result.keyword_docs.items() if name in result.proxy_keywords}
    )
    for section, keywords in matrix_41.items():
        for keyword in keywords:
            if keyword in result.proxy_keywords and keyword not in result.matrix_keywords[section]:
                if any(keyword in result.matrix_keywords[s] for s in SECTIONS_MATRIX):
                    continue
                if keyword in result.keyword_docs and result.keyword_docs[keyword].sections:
                    continue
                result.matrix_keywords[section].add(keyword)

    if section_44 >= 0:
        section_5 = _find_body_section(lines, "5")
        action_end = section_5 if section_5 >= 0 else len(lines)
        result.action_reference = parse_actions_lines(lines, section_44 + 1, action_end)
    matrix_44 = action_matrix_from_reference(result.action_reference)
    result.action_matrix = merge_action_matrices(matrix_43, matrix_44)

    known = set(result.keyword_docs.keys())
    for keywords in result.matrix_keywords.values():
        known.update(keywords)
    for keywords in result.section_keywords.values():
        known.update(keywords)

    for name in known:
        if name not in result.keyword_docs:
            result.keyword_docs[name] = KeywordDoc(
                name=name,
                signatures=[name],
                sections=_sections_for_doc(
                    name,
                    result.global_keywords,
                    result.matrix_keywords,
                    result.section_keywords,
                ),
                chapter="4.2" if name in result.proxy_keywords else "3.1",
            )
            result.signatures.setdefault(name, [name])

    result.acl_reference = parse_acl_reference(path)

    return result
