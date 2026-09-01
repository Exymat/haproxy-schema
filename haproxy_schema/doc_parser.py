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
from .logformat_doc_parser import LogformatReferenceDoc, parse_logformat_reference
from .dconv_bridge import (
    ArgumentParamDoc,
    ArgumentValueDoc,
    KeywordDoc,
    KeywordVariantDoc,
    is_valid_keyword_name,
    merge_argument_docs,
    walk_keyword_docs,
)

from .doc_layout import DocLayout, detect_doc_layout
from .legacy_action_parser import is_legacy_action_doc_keyword, parse_legacy_proxy_actions
from .line_option_docs import walk_line_option_docs
from .sample_doc_parser import SampleReferenceDoc, parse_sample_reference

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
SHARED_STANDALONE_SECTION_SPECS: tuple[tuple[str, str], ...] = (
    ("5.3.2", "resolvers"),
    ("6.2.1", "cache"),
    ("10.1.1", "fcgi-app"),
    ("8.3.5", "log-profile"),
)

_STANDALONE_SECTION_TITLE_MAP: dict[str, str] = {
    "userlists": "userlist",
    "users": "userlist",
    "peers": "peers",
    "peers declaration": "peers",
    "mailers": "mailers",
    "programs": "program",
    "programs deprecated": "program",
    "http errors": "http-errors",
    "rings": "ring",
    "log forwarding": "log-forward",
    "certificate storage": "crt-store",
    "traces": "traces",
    "acme": "acme",
    "healthchecks": "healthcheck",
}

GLOBAL_DOC_CHAPTERS = frozenset({"3.1", "3.2", "3.3"})

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
        "healthcheck",
        "acme",
        "log-forward",
        "log-profile",
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
    named_defaults_keywords: set[str] = field(default_factory=set)
    signatures: dict[str, list[str]] = field(default_factory=dict)
    keyword_docs: dict[str, KeywordDoc] = field(default_factory=dict)
    bind_option_docs: dict[str, KeywordDoc] = field(default_factory=dict)
    server_option_docs: dict[str, KeywordDoc] = field(default_factory=dict)
    acl_reference: AclReferenceDoc = field(default_factory=AclReferenceDoc)
    sample_reference: SampleReferenceDoc = field(default_factory=SampleReferenceDoc)
    logformat_reference: LogformatReferenceDoc = field(default_factory=LogformatReferenceDoc)
    hapee_only_keywords: set[str] = field(default_factory=set)


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


def _normalize_heading_title(title: str) -> str:
    title = re.sub(r"\([^)]*\)", " ", title)
    title = title.replace("-", " ")
    title = re.sub(r"[^a-z0-9\s]", " ", title.lower())
    return re.sub(r"\s+", " ", title).strip()


def _iter_body_headings(lines: list[str]) -> list[tuple[str, str, int]]:
    header_re = re.compile(r"^(\d+(?:\.\d+)*)\.\s+(.+?)\s*$")
    headings: list[tuple[str, str, int]] = []
    for idx, line in enumerate(lines):
        match = header_re.match(line.strip())
        if not match:
            continue
        underline = _next_nonblank(lines, idx + 1)
        if underline and set(underline.strip()) == {"-"}:
            headings.append((match.group(1), match.group(2).strip(), idx))
    return headings


def _walk_chapter_section(lines: list[str], section_id: str) -> dict[str, KeywordDoc]:
    """Extract keyword docs for one configuration.txt chapter (e.g. 3.1, 3.2)."""
    start = _find_body_section(lines, section_id)
    if start < 0:
        return {}
    end = _find_subsection_end(lines, section_id, start)
    return _filter_keyword_docs(walk_keyword_docs(lines, start, end, section_id))


def _walk_filter_directive_docs(lines: list[str]) -> dict[str, KeywordDoc]:
    """Extract proxy filter directives documented in chapter 9 (e.g. filter cache)."""
    start = _find_body_section(lines, "9")
    if start < 0:
        return {}
    end = _find_subsection_end(lines, "9", start)
    raw = walk_keyword_docs(lines, start, end, "9")
    return {
        name: doc
        for name, doc in raw.items()
        if name.startswith("filter ") and is_valid_keyword_name(name)
    }


def _walk_chapter3_globals(
    lines: list[str],
    *,
    extra_chapters: tuple[str, ...] = (),
) -> dict[str, KeywordDoc]:
    """Global-section keywords from doc chapters 3.1-3.3 (and HAPEE extras), each with its own chapter id."""
    merged: dict[str, KeywordDoc] = {}
    for section_id in ("3.1", "3.2", "3.3") + extra_chapters:
        _merge_keyword_docs(merged, _walk_chapter_section(lines, section_id))
    return merged


def _httpclient_tuning_section(layout: DocLayout) -> str:
    """Doc section id for global HTTPClient tuning keywords."""
    # 3.2+ documents HTTPClient under 3.4; legacy 2.x/3.0 docs use 3.11.
    return "3.11" if layout.standalone == "chapter3" else "3.4"


def _extract_4_1_matrix(
    lines: list[str], start_idx: int, end_idx: int
) -> tuple[dict[str, set[str]], set[str], set[str]]:
    out = {name: set() for name in SECTIONS_MATRIX}
    no_prefix: set[str] = set()
    named_defaults: set[str] = set()
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
                if section == "defaults" and "(!)" in col:
                    named_defaults.add(keyword)
    return out, no_prefix, named_defaults


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


def _merge_variant_docs(
    target: KeywordVariantDoc,
    source: KeywordVariantDoc,
    *,
    prefer_source_description: bool = False,
) -> None:
    for section in source.sections:
        if section not in target.sections:
            target.sections.append(section)
    for sig in source.signatures:
        if sig not in target.signatures:
            target.signatures.append(sig)
    for context in source.contexts:
        if context not in target.contexts:
            target.contexts.append(context)
    if source.description:
        if prefer_source_description or not target.description:
            target.description = source.description
    if source.arguments:
        merge_argument_docs(target, source.arguments)
    if source.examples and not target.examples:
        target.examples = list(source.examples)


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
                variants=[
                    KeywordVariantDoc(
                        chapter=variant.chapter,
                        sections=list(variant.sections),
                        signatures=list(variant.signatures),
                        description=variant.description,
                        examples=list(variant.examples),
                        contexts=list(variant.contexts),
                        arguments=[
                            ArgumentParamDoc(
                                parameter=argument.parameter,
                                description=argument.description,
                                values=[
                                    ArgumentValueDoc(name=value.name, description=value.description)
                                    for value in argument.values
                                ],
                            )
                            for argument in variant.arguments
                        ],
                    )
                    for variant in doc.variants
                ],
            )
            continue
        for variant in doc.variants:
            merged = entry.variant_for(
                variant.chapter,
                signatures=variant.signatures,
                sections=variant.sections,
            )
            _merge_variant_docs(
                merged,
                variant,
                prefer_source_description=prefer_source_description,
            )


def _sections_for_keyword(matrix: dict[str, set[str]], name: str) -> list[str]:
    return [section for section in SECTIONS_MATRIX if name in matrix.get(section, set())]


def _matrix_from_proxy_docs(keyword_docs: dict[str, KeywordDoc]) -> dict[str, set[str]]:
    """Build section applicability from 4.2 keyword blocks (authoritative for proxy keywords)."""
    out = {name: set() for name in SECTIONS_MATRIX}
    for kw_name, doc in keyword_docs.items():
        if not is_valid_keyword_name(kw_name):
            continue
        for variant in doc.variants:
            if variant.chapter != "4.2":
                continue
            for section in variant.sections:
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


def _standalone_specs_for_layout(
    lines: list[str],
    layout: DocLayout,
) -> tuple[tuple[str, str], ...]:
    specs: list[tuple[str, str]] = list(SHARED_STANDALONE_SECTION_SPECS)
    for section_id, title, _ in _iter_body_headings(lines):
        if layout.standalone == "chapter12":
            if not (section_id.startswith("11.") or section_id.startswith("12.")):
                continue
        elif not section_id.startswith("3."):
            continue
        config_section = _STANDALONE_SECTION_TITLE_MAP.get(_normalize_heading_title(title))
        if config_section is None or config_section == "crt-list":
            continue
        specs.append((section_id, config_section))
    return tuple(dict.fromkeys(specs))


def _section_chapters_from_specs(
    specs: tuple[tuple[str, str], ...],
) -> dict[str, set[str]]:
    section_chapters: dict[str, set[str]] = {}
    for section_id, config_section in specs:
        section_chapters.setdefault(config_section, set()).add(section_id)
    return section_chapters


def _parse_standalone_sections(
    lines: list[str],
    specs: tuple[tuple[str, str], ...] | None = None,
) -> tuple[dict[str, set[str]], dict[str, KeywordDoc], dict[str, set[str]]]:
    """Extract keywords documented for non-proxy sections (cache, peers, …)."""
    from .dconv_bridge import walk_keyword_docs

    layout = detect_doc_layout(lines)
    if specs is None:
        specs = _standalone_specs_for_layout(lines, layout)
    section_keywords: dict[str, set[str]] = {}
    merged_docs: dict[str, KeywordDoc] = {}
    section_chapters = _section_chapters_from_specs(specs)

    for section_id, config_section in specs:
        start = _find_body_section(lines, section_id)
        if start < 0:
            continue
        end = _find_subsection_end(lines, section_id, start)
        docs = walk_keyword_docs(lines, start, end, section_id)
        inner = {
            name: doc
            for name, doc in docs.items()
            if (
                name not in _SECTION_DECLARATION_KEYWORDS or name == config_section
            )
            and _is_standalone_directive(name)
        }
        if inner:
            bucket = section_keywords.setdefault(config_section, set())
            bucket.update(name for name in inner if name != config_section)
            for doc in inner.values():
                for variant in doc.variants_for(section_id):
                    if config_section not in variant.sections:
                        variant.sections.append(config_section)
            _merge_keyword_docs(merged_docs, inner)

    # Load options apply inside crt-list, but their chapter id differs across layouts.
    crt_list_section_id = "12.7.1" if layout.standalone != "chapter3" else "3.12.1"
    crt_list_start = _find_body_section(lines, crt_list_section_id)
    if crt_list_start >= 0:
        crt_list_end = _find_subsection_end(lines, crt_list_section_id, crt_list_start)
        load_docs = walk_keyword_docs(lines, crt_list_start, crt_list_end, crt_list_section_id)
        load_docs = {
            name: doc
            for name, doc in load_docs.items()
            if name not in _SECTION_DECLARATION_KEYWORDS and _is_standalone_directive(name)
        }
        if load_docs:
            bucket = section_keywords.setdefault("crt-list", set())
            bucket.update(load_docs.keys())
            for doc in load_docs.values():
                for variant in doc.variants_for(crt_list_section_id):
                    if "crt-list" not in variant.sections:
                        variant.sections.append("crt-list")
            _merge_keyword_docs(merged_docs, load_docs)
            section_chapters.setdefault("crt-list", set()).add(crt_list_section_id)

    return section_keywords, merged_docs, section_chapters


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


def _sections_for_variant(
    name: str,
    variant: KeywordVariantDoc,
    global_keywords: set[str],
    matrix: dict[str, set[str]],
    section_keywords: dict[str, set[str]] | None = None,
    section_chapters: dict[str, set[str]] | None = None,
    *,
    global_doc_chapters: frozenset[str] = GLOBAL_DOC_CHAPTERS,
) -> list[str]:
    """Assign config sections to one chapter-specific keyword variant without cross-contamination."""
    sections = list(dict.fromkeys(variant.sections))
    if variant.chapter in global_doc_chapters and name in global_keywords:
        if "global" not in sections:
            sections.insert(0, "global")
    if variant.chapter == "4.2":
        for section in _sections_for_keyword(matrix, name):
            if section not in sections:
                sections.append(section)
    if section_keywords:
        for config_section, keywords in section_keywords.items():
            if name not in keywords or config_section in sections:
                continue
            allowed_chapters = section_chapters.get(config_section) if section_chapters else None
            if allowed_chapters and variant.chapter not in allowed_chapters:
                continue
            sections.append(config_section)
    return sections


def parse_configuration(path: Path) -> DocParseResult:
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_configuration_lines(text.splitlines(), reference_doc_path=path)


def parse_configuration_lines(
    lines: list[str],
    *,
    global_doc_chapters: frozenset[str] = GLOBAL_DOC_CHAPTERS,
    reference_doc_path: Path | None = None,
) -> DocParseResult:
    extra_global_chapters = tuple(
        chapter
        for chapter in sorted(global_doc_chapters - GLOBAL_DOC_CHAPTERS, key=lambda c: [int(p) for p in c.split(".")])
    )

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

    layout = detect_doc_layout(lines)
    has_section_44 = _find_body_section(lines, "4.4") >= 0
    section_5 = _find_body_section(lines, "5")

    result = DocParseResult()

    matrix_41, result.no_prefix_keywords, result.named_defaults_keywords = _extract_4_1_matrix(
        lines, section_41, section_42
    )
    matrix_43 = (
        _extract_4_3_actions_matrix(lines, section_43, section_44)
        if section_43 < section_44
        else {name: set() for name in ACTION_MATRIX_GROUP_KEYS}
    )

    # Only 3.1-3.3 directives belong in the HAProxy "global" section (not peers, userlists, etc.).
    global_docs = _walk_chapter3_globals(lines, extra_chapters=extra_global_chapters)
    other_chapter3_docs = _walk_chapter_section(lines, _httpclient_tuning_section(layout))
    if layout.actions == "modern":
        proxy_docs_end = section_43
    else:
        proxy_docs_end = section_5 if section_5 >= 0 else len(lines)
    proxy_docs = _filter_keyword_docs(walk_keyword_docs(lines, section_42, proxy_docs_end, "4.2"))
    if layout.actions == "legacy":
        proxy_docs = {
            name: doc for name, doc in proxy_docs.items() if not is_legacy_action_doc_keyword(name)
        }
    result.proxy_keywords = set(proxy_docs.keys())
    _merge_keyword_docs(result.keyword_docs, global_docs)
    _merge_keyword_docs(result.keyword_docs, other_chapter3_docs)
    _merge_keyword_docs(result.keyword_docs, proxy_docs, prefer_source_description=True)

    filter_directive_docs = _walk_filter_directive_docs(lines)
    if filter_directive_docs:
        _merge_keyword_docs(result.keyword_docs, filter_directive_docs, prefer_source_description=True)
        result.proxy_keywords.update(filter_directive_docs.keys())

    result.section_keywords, standalone_docs, standalone_section_chapters = _parse_standalone_sections(lines)
    standalone_docs = _filter_keyword_docs(standalone_docs)
    _merge_keyword_docs(result.keyword_docs, standalone_docs)

    result.global_keywords = set(global_docs.keys())

    for name, doc in result.keyword_docs.items():
        result.signatures[name] = list(doc.signatures)
        for variant in doc.variants:
            variant.sections = _sections_for_variant(
                name,
                variant,
                result.global_keywords,
                matrix_41,
                result.section_keywords,
                standalone_section_chapters,
                global_doc_chapters=global_doc_chapters,
            )
        if not doc.sections and " " in name and name in result.proxy_keywords:
            prefix = name.split()[0]
            inherited_sections: list[str] = []
            prefix_doc = result.keyword_docs.get(prefix)
            if prefix_doc:
                for prefix_variant in prefix_doc.variants:
                    if prefix_variant.sections:
                        inherited_sections = list(prefix_variant.sections)
                        break
            if not inherited_sections:
                for sibling_name, sibling_doc in result.keyword_docs.items():
                    if sibling_name.startswith(f"{prefix} "):
                        for sibling_variant in sibling_doc.variants:
                            if sibling_variant.chapter == "4.2" and sibling_variant.sections:
                                inherited_sections = list(sibling_variant.sections)
                                break
                    if inherited_sections:
                        break
            if inherited_sections:
                for variant in doc.variants:
                    if not variant.sections:
                        variant.sections = list(inherited_sections)
                proxy_variants = [variant for variant in doc.variants if variant.chapter == "4.2"]
                if proxy_variants:
                    proxy_variant = proxy_variants[0]
                    proxy_variant.sections = _sections_for_variant(
                        name,
                        proxy_variant,
                        result.global_keywords,
                        matrix_41,
                        result.section_keywords,
                        standalone_section_chapters,
                        global_doc_chapters=global_doc_chapters,
                    )
                    if not proxy_variant.sections:
                        proxy_variant.sections = list(inherited_sections)

    # Section 4.2 is authoritative for proxy keyword inventory and section applicability.
    result.matrix_keywords = _matrix_from_proxy_docs(
        {name: doc for name, doc in result.keyword_docs.items() if name in result.proxy_keywords}
    )
    for section, keywords in matrix_41.items():
        for keyword in keywords:
            if keyword in result.proxy_keywords and keyword not in result.matrix_keywords[section]:
                if any(keyword in result.matrix_keywords[s] for s in SECTIONS_MATRIX):
                    continue
                proxy_variant = result.keyword_docs[keyword].variant_for("4.2")
                if keyword in result.keyword_docs and proxy_variant.sections:
                    continue
                result.matrix_keywords[section].add(keyword)

    if has_section_44:
        action_end = section_5 if section_5 >= 0 else len(lines)
        result.action_reference = parse_actions_lines(lines, section_44 + 1, action_end)
        matrix_44 = action_matrix_from_reference(result.action_reference)
        result.action_matrix = merge_action_matrices(matrix_43, matrix_44)
    elif layout.actions == "legacy":
        legacy_end = section_5 if section_5 >= 0 else len(lines)
        result.action_reference, result.action_matrix = parse_legacy_proxy_actions(
            lines, section_42, legacy_end
        )
    else:
        result.action_matrix = merge_action_matrices(
            matrix_43, action_matrix_from_reference(result.action_reference)
        )

    known = set(result.keyword_docs.keys())
    for keywords in result.matrix_keywords.values():
        known.update(keywords)
    for keywords in result.section_keywords.values():
        known.update(keywords)

    for name in known:
        if name not in result.keyword_docs:
            chapter = "4.2" if name in result.proxy_keywords else "3.1"
            placeholder = KeywordVariantDoc(
                chapter=chapter,
                signatures=[name],
                sections=_sections_for_doc(
                    name,
                    result.global_keywords,
                    result.matrix_keywords,
                    result.section_keywords,
                ),
            )
            result.keyword_docs[name] = KeywordDoc(name=name, variants=[placeholder])
            result.signatures.setdefault(name, [name])

    section_51 = _find_body_section(lines, "5.1")
    section_52 = _find_body_section(lines, "5.2")
    if section_51 >= 0:
        bind_end = section_52 if section_52 >= 0 else (section_5 if section_5 >= 0 else len(lines))
        result.bind_option_docs = walk_line_option_docs(lines, section_51, bind_end, "5.1")
    if section_52 >= 0:
        server_end = section_5 if section_5 >= 0 else len(lines)
        section_53 = _find_body_section(lines, "5.3")
        if section_53 >= 0:
            server_end = section_53
        result.server_option_docs = walk_line_option_docs(lines, section_52, server_end, "5.2")

    reference_path = reference_doc_path
    if reference_path is not None and reference_path.is_file():
        result.acl_reference = parse_acl_reference(reference_path)
        result.sample_reference = parse_sample_reference(reference_path)
        result.logformat_reference = parse_logformat_reference(reference_path)

    return result
