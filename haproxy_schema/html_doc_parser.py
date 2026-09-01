"""Parse HAProxy Enterprise dconv HTML documentation into DocParseResult."""

from __future__ import annotations

from copy import deepcopy
from html import unescape
import re
from pathlib import Path
from urllib.request import urlopen

from bs4 import BeautifulSoup, NavigableString, Tag

from .dconv_bridge import extract_keyword_name
from .doc_parser import (
    GLOBAL_DOC_CHAPTERS,
    DocParseResult,
    _merge_keyword_docs,
    parse_configuration,
    parse_configuration_lines,
)
from .hapee_versions import HapeeRelease, default_oss_configuration_txt, hapee_release
from .sample_doc_parser import SampleDoc, SampleReferenceDoc

_CHAPTER_H2_RE = re.compile(r"^chapter-(\d+(?:\.\d+)*)$")
_ARGUMENT_LABEL_RE = re.compile(r"^arguments?\s*:?\s*$", re.I)
_EXAMPLE_LABEL_RE = re.compile(r"^examples?\s*:?\s*$", re.I)
_SEE_ALSO_LABEL_RE = re.compile(r"^see also\s*:?\s*$", re.I)
_MODULES_HEADING_RE = re.compile(r"^(\d+(?:\.\d+)*)\.\s+Modules\s*$", re.I)


def load_hapee_html(*, path: Path | None = None, url: str | None = None) -> str:
    if path is not None:
        return path.read_text(encoding="utf-8", errors="replace")
    if url is not None:
        with urlopen(url) as response:
            return response.read().decode("utf-8", errors="replace")
    raise ValueError("Either path or url must be provided")


def _tag_text(node: Tag | NavigableString | None) -> str:
    if node is None:
        return ""
    if isinstance(node, NavigableString):
        return unescape(str(node))
    return unescape(node.get_text())


def _keyword_signature(keyword_div: Tag) -> str:
    # dconv splits signatures across inline elements. BeautifulSoup's separator
    # must preserve a space between config arguments, but must not turn
    # ``has_ctl([mask])`` into the different keyword ``has_ctl ``.
    signature = re.sub(r"\s+", " ", unescape(keyword_div.get_text(" ", strip=True))).strip()
    signature = re.sub(r"\s*\(\s*", "(", signature)
    signature = re.sub(r"\s*\)\s*", ")", signature)
    signature = re.sub(r"\s*,\s*", ", ", signature)
    return signature


def _table_cell_mark(cell: Tag) -> str:
    if cell.find("img"):
        alt = ""
        img = cell.find("img")
        if img is not None:
            alt = (img.get("alt") or img.get("title") or "").strip()
        if "(!)" in alt or "yes (!)" in (img.get("title") or ""):
            return "X (!)"
        if alt.upper() == "X" or "yes" in alt.lower():
            return "X"
        return "X"
    text = cell.get_text().strip()
    if not text or text == "\xa0":
        # A visible placeholder is essential: the text parser splits on runs
        # of whitespace, so an empty cell would move every later X one column
        # to the left.
        return "-"
    if "X" in text.upper():
        return text
    return "-"


def _matrix_lines_from_table(table: Tag) -> list[str]:
    rows = table.find_all("tr")
    if not rows:
        return []
    lines: list[str] = []
    for row in rows:
        cells = row.find_all(["th", "td"])
        if not cells:
            continue
        texts = [_tag_text(cell).strip() for cell in cells]
        if texts[0].lower() == "keyword":
            lines.append("  ".join(texts))
            continue
        keyword = texts[0]
        if not keyword:
            continue
        marks = [_table_cell_mark(cell) for cell in cells[1:]]
        while len(marks) < 4:
            marks.append("-")
        lines.append("  ".join([keyword, *marks]))
    return lines


def _pre_lines(pre: Tag) -> list[str]:
    code = pre.find("code")
    source = code if code is not None else pre
    text = source.get_text("\n", strip=False)
    return [line.rstrip() for line in text.splitlines()]


def _convert_separator(separator: Tag) -> list[str]:
    label_span = separator.find("span")
    label = _tag_text(label_span).strip() if label_span else ""
    lines: list[str] = []
    if _ARGUMENT_LABEL_RE.match(label):
        lines.append("Arguments :")
        pre = separator.find("pre", class_="arguments")
        if pre is not None:
            for line in _pre_lines(pre):
                lines.append(f"   {line}" if line else "")
    elif _EXAMPLE_LABEL_RE.match(label):
        lines.append("Example:")
        pre = separator.find("pre")
        if pre is not None:
            desc = pre.find(class_="example-desc")
            if desc is not None:
                lines.append(f"   {desc.get_text(strip=True)}")
            for line in _pre_lines(pre):
                if line:
                    lines.append(f"   {line}")
    elif _SEE_ALSO_LABEL_RE.match(label):
        lines.append(f"See also: {_tag_text(separator).replace(label, '', 1).strip()}")
    return lines


def _convert_block(node: Tag | NavigableString) -> list[str]:
    if isinstance(node, NavigableString):
        text = str(node).strip()
        return [text] if text else []

    if not isinstance(node, Tag):
        return []

    if node.name == "div" and "keyword" in (node.get("class") or []):
        return [_keyword_signature(node)]

    if node.name == "div" and "text" in (node.get("class") or []):
        text = node.get_text(" ", strip=True)
        if not text:
            return []
        return [text]

    if node.name == "div" and "separator" in (node.get("class") or []):
        return _convert_separator(node)

    if node.name == "table" and "table-bordered" in (node.get("class") or []):
        return _matrix_lines_from_table(node)

    if node.name == "pre" and "text" in (node.get("class") or []):
        return node.get_text("\n", strip=False).splitlines()

    if node.name == "h5":
        title = node.get_text(strip=True)
        if title:
            return [title, "-" * len(title)]
        return []

    lines: list[str] = []
    for child in node.children:
        lines.extend(_convert_block(child))
    return lines


def _chapter_title(heading: Tag) -> tuple[str, str]:
    chapter_id = heading.get("data-target") or ""
    if not chapter_id:
        match = _CHAPTER_H2_RE.match(heading.get("id") or "")
        chapter_id = match.group(1) if match else ""
    title = heading.get_text(" ", strip=True)
    title = re.sub(r"^\d+(?:\.\d+)*\.\s*", "", title).strip()
    return chapter_id, title


def _is_chapter_heading(node: Tag | NavigableString | None) -> bool:
    return (
        isinstance(node, Tag)
        and node.name in {"h2", "h3"}
        and (node.get("id") or "").startswith("chapter-")
    )


def html_to_configuration_lines(html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    chapters = soup.select('h2[id^="chapter-"], h3[id^="chapter-"]')
    lines: list[str] = ["Configuration Manual", "-------------------", "Summary", "-------"]
    for heading in chapters:
        chapter_id, title = _chapter_title(heading)
        if not chapter_id:
            continue
        lines.append(f"{chapter_id}. {title}")
        lines.append("-" * max(len(f"{chapter_id}. {title}"), 3))
        lines.append("")
        sibling = heading.next_sibling
        while sibling is not None:
            if _is_chapter_heading(sibling):
                break
            if isinstance(sibling, Tag):
                for block_line in _convert_block(sibling):
                    lines.append(block_line)
            sibling = sibling.next_sibling
        lines.append("")
    return lines


def _sample_chapter_nodes(heading: Tag) -> list[Tag]:
    nodes: list[Tag] = []
    sibling = heading.next_sibling
    while sibling is not None:
        if _is_chapter_heading(sibling):
            break
        if isinstance(sibling, Tag):
            nodes.append(sibling)
        sibling = sibling.next_sibling
    return nodes


def _merge_sample_table_row(
    row: Tag,
    bucket: dict[str, SampleDoc],
    *,
    chapter: str,
    converters: bool,
) -> None:
    cells = row.find_all(["th", "td"])
    if len(cells) < 2:
        return
    signature = _normalize_sample_signature(_tag_text(cells[0]))
    if not signature or signature.lower() == "keyword":
        return
    name = _sample_name(signature)
    if not name:
        return
    item = bucket.setdefault(name, SampleDoc(name=name, chapter=chapter))
    if not item.signature:
        item.signature = signature
    item.chapter = chapter
    if converters and len(cells) >= 3:
        item.input_type = item.input_type or _tag_text(cells[1]).strip()
        item.output_type = item.output_type or _tag_text(cells[2]).strip()
    elif not converters:
        item.output_type = item.output_type or _tag_text(cells[-1]).strip()


def _merge_sample_keyword_div(
    keyword_div: Tag,
    bucket: dict[str, SampleDoc],
    *,
    chapter: str,
) -> None:
    signature = _normalize_sample_signature(_keyword_signature(keyword_div))
    name = _sample_name(signature)
    # Detailed entries enrich the canonical summary inventory. They must not
    # create new functions from example/prose keyword blocks.
    if not name or name not in bucket:
        return
    item = bucket[name]
    if signature and (not item.signature or len(signature) > len(item.signature)):
        item.signature = signature
    item.chapter = chapter
    desc_node = keyword_div.find_next_sibling("div")
    if isinstance(desc_node, Tag) and "text" in (desc_node.get("class") or []):
        description = desc_node.get_text(" ", strip=True)
        if description and not item.description:
            item.description = description


_SAMPLE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_TRAILING_SAMPLE_TYPE_RE = re.compile(r"\s*:\s*[A-Za-z][A-Za-z0-9_./+ -]*$")


def _normalize_sample_signature(signature: str) -> str:
    signature = re.sub(r"\s+", " ", unescape(signature)).strip()
    signature = _TRAILING_SAMPLE_TYPE_RE.sub("", signature).strip()
    signature = re.sub(r"\s*\(\s*", "(", signature)
    signature = re.sub(r"\s*\)\s*", ")", signature)
    signature = re.sub(r"\s*,\s*", ", ", signature)
    return signature


def _sample_name(signature: str) -> str:
    name = extract_keyword_name(signature).strip() if signature else ""
    return name if _SAMPLE_NAME_RE.fullmatch(name) else ""


def _is_sample_summary_table(table: Tag, *, converters: bool) -> bool:
    first_row = table.find("tr")
    if first_row is None:
        return False
    cells = first_row.find_all(["th", "td"], recursive=False)
    headings = [re.sub(r"\s+", " ", _tag_text(cell)).strip().lower() for cell in cells]
    if not headings or headings[0] != "keyword":
        return False
    if converters:
        return len(headings) >= 3 and "input" in headings[1] and "output" in headings[2]
    return len(headings) >= 2 and "output" in headings[-1]


def parse_sample_reference_html(html: str) -> SampleReferenceDoc:
    """Extract converters (7.3.1) and sample fetches (7.3.2–7.3.7) from HAPEE HTML."""
    soup = BeautifulSoup(html, "html.parser")
    out = SampleReferenceDoc()
    for heading in soup.select('h3[id^="chapter-7.3."]'):
        chapter_id, _title = _chapter_title(heading)
        if not chapter_id:
            continue
        converters = chapter_id == "7.3.1"
        bucket = out.converters if converters else out.fetches
        for node in _sample_chapter_nodes(heading):
            tables = [node] if node.name == "table" else []
            tables.extend(node.find_all("table"))
            for table in tables:
                if not _is_sample_summary_table(table, converters=converters):
                    continue
                for row in table.find_all("tr"):
                    if row.find_parent("table") is not table:
                        continue
                    _merge_sample_table_row(row, bucket, chapter=chapter_id, converters=converters)
            keyword_divs: list[Tag] = []
            if node.name == "div" and "keyword" in (node.get("class") or []):
                keyword_divs.append(node)
            keyword_divs.extend(
                tag for tag in node.find_all("div") if "keyword" in (tag.get("class") or [])
            )
            for keyword_div in keyword_divs:
                _merge_sample_keyword_div(keyword_div, bucket, chapter=chapter_id)
    return out


def _overlay_doc_parse_result(base: DocParseResult, enterprise: DocParseResult) -> DocParseResult:
    """Return the complete OSS parse with Enterprise additions overlaid on it."""
    result = deepcopy(base)
    result.global_keywords.update(enterprise.global_keywords)
    result.proxy_keywords.update(enterprise.proxy_keywords)
    result.no_prefix_keywords.update(enterprise.no_prefix_keywords)
    result.named_defaults_keywords.update(enterprise.named_defaults_keywords)

    for field_name in ("matrix_keywords", "section_keywords", "action_matrix"):
        target = getattr(result, field_name)
        source = getattr(enterprise, field_name)
        for group, names in source.items():
            target.setdefault(group, set()).update(names)

    for name, signatures in enterprise.signatures.items():
        merged = result.signatures.setdefault(name, [])
        for signature in signatures:
            if signature not in merged:
                merged.append(signature)

    _merge_keyword_docs(result.keyword_docs, enterprise.keyword_docs, prefer_source_description=True)
    _merge_keyword_docs(result.bind_option_docs, enterprise.bind_option_docs, prefer_source_description=True)
    _merge_keyword_docs(result.server_option_docs, enterprise.server_option_docs, prefer_source_description=True)

    for name, action in enterprise.action_reference.items():
        existing = result.action_reference.get(name)
        if existing is None:
            result.action_reference[name] = deepcopy(action)
            continue
        if action.signature:
            existing.signature = action.signature
        if action.description:
            existing.description = action.description
        if action.examples:
            existing.examples = deepcopy(action.examples)
        for ruleset in action.rulesets:
            if ruleset not in existing.rulesets:
                existing.rulesets.append(ruleset)
        existing.usable_in = action.usable_in or existing.usable_in
        existing.docs_keyword = action.docs_keyword or existing.docs_keyword
        existing.chapter = action.chapter or existing.chapter

    result.sample_reference.converters.update(deepcopy(enterprise.sample_reference.converters))
    result.sample_reference.fetches.update(deepcopy(enterprise.sample_reference.fetches))
    result.hapee_only_keywords = set(enterprise.hapee_only_keywords)
    return result


def _all_doc_keywords(doc: DocParseResult) -> set[str]:
    keywords: set[str] = set(doc.global_keywords) | set(doc.proxy_keywords)
    keywords.update(doc.signatures.keys())
    for bucket in doc.matrix_keywords.values():
        keywords.update(bucket)
    for bucket in doc.section_keywords.values():
        keywords.update(bucket)
    for bucket in doc.action_matrix.values():
        keywords.update(bucket)
    keywords.update(doc.bind_option_docs.keys())
    keywords.update(doc.server_option_docs.keys())
    return keywords


def modules_chapter_id(lines: list[str]) -> str | None:
    """Chapter id of the HAPEE Modules section (module-load / module-path), if present."""
    for line in lines:
        match = _MODULES_HEADING_RE.match(line.strip())
        if match:
            return match.group(1)
    return None


def parse_configuration_html(
    html: str,
    *,
    release: HapeeRelease,
    oss_reference_doc: Path | None = None,
) -> DocParseResult:
    lines = html_to_configuration_lines(html)
    extra_chapters = set(release.extra_global_chapters)
    detected_modules = modules_chapter_id(lines)
    if detected_modules:
        extra_chapters.add(detected_modules)
    global_chapters = GLOBAL_DOC_CHAPTERS | frozenset(extra_chapters)
    enterprise = parse_configuration_lines(
        lines,
        global_doc_chapters=global_chapters,
        reference_doc_path=None,
    )
    html_samples = parse_sample_reference_html(html)
    enterprise.sample_reference.converters.update(html_samples.converters)
    enterprise.sample_reference.fetches.update(html_samples.fetches)
    if oss_reference_doc is not None and oss_reference_doc.is_file():
        oss_doc = parse_configuration(oss_reference_doc)
        enterprise.hapee_only_keywords = _all_doc_keywords(enterprise) - _all_doc_keywords(oss_doc)
        return _overlay_doc_parse_result(oss_doc, enterprise)
    return enterprise


def parse_hapee_configuration(
    *,
    html_path: Path | None = None,
    fetch_url: str | None = None,
    hapee_version: str,
    oss_reference_doc: Path | None = None,
) -> DocParseResult:
    release = hapee_release(hapee_version)
    html = load_hapee_html(path=html_path, url=fetch_url or release.doc_url)
    if oss_reference_doc is None:
        try:
            oss_reference_doc = default_oss_configuration_txt(
                release.oss_base,
                monorepo_root=None,
            )
        except FileNotFoundError:
            oss_reference_doc = None
    return parse_configuration_html(
        html,
        release=release,
        oss_reference_doc=oss_reference_doc,
    )
