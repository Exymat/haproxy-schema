"""Parse stick-table declaration arguments from configuration.txt section 11.1."""

from __future__ import annotations

import re

from .dconv_bridge import ArgumentParamDoc, ArgumentValueDoc, KeywordDoc, merge_argument_docs

_STICK_TABLE_KEYWORDS = ("stick-table type", "table")

_ARG_BULLET_RE = re.compile(
    r"^ {2,}- ([a-z][a-z0-9_-]*)(?:\s+(<[^>]+>))?(?:\s{2,}(.*))?$",
    re.I,
)
_TYPE_VALUE_RE = re.compile(
    r"^ {4,}\* ([a-z][a-z0-9_-]*)(?:\s+\[[^\]]+\])?\s*(.*)$",
    re.I,
)
_STORE_TYPE_RE = re.compile(
    r"^ {2,}- ([a-z][a-z0-9_]*(?:\([^)]+\))?)\s*(?:\[.*\])?\s*$",
    re.I,
)
_STORE_SECTION_RE = re.compile(
    r"the data types that can be associated with an entry",
    re.I,
)


def _append_text(existing: str, addition: str) -> str:
    piece = addition.strip()
    if not piece:
        return existing
    if not existing:
        return piece
    return f"{existing} {piece}"


def _declaration_range(lines: list[str]) -> tuple[int, int]:
    from .doc_parser import _find_subsection_end, _iter_body_headings, _normalize_heading_title

    for section_id, title, idx in _iter_body_headings(lines):
        normalized = _normalize_heading_title(title)
        if "stick table" in normalized and "declar" in normalized:
            return idx, _find_subsection_end(lines, section_id, idx)
    return -1, -1


def _parse_declaration_arguments(lines: list[str], start: int, end: int) -> list[ArgumentParamDoc]:
    params: list[ArgumentParamDoc] = []
    current: ArgumentParamDoc | None = None
    collecting_type_values = False
    idx = start
    while idx < end:
        line = lines[idx]
        stripped = line.strip()
        if _STORE_SECTION_RE.search(stripped):
            break
        if stripped.lower().startswith("example") or stripped.lower().startswith("see also"):
            break

        type_match = _TYPE_VALUE_RE.match(line)
        if type_match and current is not None:
            collecting_type_values = True
            name = type_match.group(1)
            desc = (type_match.group(2) or "").strip()
            current.values.append(ArgumentValueDoc(name=name, description=desc))
            idx += 1
            continue

        bullet = _ARG_BULLET_RE.match(line)
        if bullet:
            if current is not None:
                params.append(current)
            name = bullet.group(1)
            placeholder = bullet.group(2) or ""
            desc = (bullet.group(3) or "").strip()
            parameter = f"{name} {placeholder}".strip() if placeholder else name
            current = ArgumentParamDoc(parameter=parameter, description=desc)
            collecting_type_values = name.lower() == "type"
            if not collecting_type_values:
                current.values.append(ArgumentValueDoc(name=name, description=desc))
            idx += 1
            continue

        if current is not None and line.startswith(" ") and stripped:
            if collecting_type_values and current.values:
                current.values[-1].description = _append_text(current.values[-1].description, stripped)
            else:
                current.description = _append_text(current.description, stripped)
                if current.values:
                    current.values[0].description = current.description
        idx += 1

    if current is not None:
        params.append(current)
    return params


def _parse_store_types(lines: list[str], start: int, end: int) -> list[ArgumentValueDoc]:
    values: list[ArgumentValueDoc] = []
    idx = start
    while idx < end:
        line = lines[idx]
        stripped = line.strip()
        if stripped.lower().startswith("example") or stripped.lower().startswith("see also"):
            break
        store_match = _STORE_TYPE_RE.match(line)
        if store_match:
            values.append(ArgumentValueDoc(name=store_match.group(1), description=""))
            idx += 1
            continue
        if values and line.startswith(" ") and stripped:
            values[-1].description = _append_text(values[-1].description, stripped)
        idx += 1
    return values


def _normalize_type_param(params: list[ArgumentParamDoc]) -> None:
    """Expose key types as values of <type> so hover and slot enrichment can find them."""
    type_param = next((param for param in params if param.parameter.lower().startswith("type")), None)
    if type_param is None:
        return
    if not type_param.values:
        return
    type_param.parameter = "<type>"


def _attach_store_types(params: list[ArgumentParamDoc], store_types: list[ArgumentValueDoc]) -> None:
    if not store_types:
        return
    store_param = next((param for param in params if param.parameter.lower().startswith("store")), None)
    if store_param is None:
        store_param = ArgumentParamDoc(parameter="store <data_type>")
        params.append(store_param)
    existing = {value.name.lower() for value in store_param.values}
    for value in store_types:
        if value.name.lower() in existing:
            continue
        store_param.values.append(value)
        existing.add(value.name.lower())


def parse_stick_table_declaration_arguments(lines: list[str]) -> list[ArgumentParamDoc]:
    start, end = _declaration_range(lines)
    if start < 0:
        return []

    args_idx = next(
        (
            idx
            for idx in range(start, end)
            if lines[idx].lstrip().lower().startswith("arguments")
        ),
        -1,
    )
    if args_idx < 0:
        return []

    store_idx = next(
        (idx for idx in range(args_idx + 1, end) if _STORE_SECTION_RE.search(lines[idx])),
        end,
    )
    params = _parse_declaration_arguments(lines, args_idx + 1, store_idx)
    store_args_idx = next(
        (
            idx
            for idx in range(store_idx, end)
            if lines[idx].lstrip().lower().startswith("arguments")
        ),
        -1,
    )
    store_types = _parse_store_types(lines, store_args_idx + 1, end) if store_args_idx >= 0 else []
    _normalize_type_param(params)
    _attach_store_types(params, store_types)
    return params


def supplement_stick_table_docs(keyword_docs: dict[str, KeywordDoc], lines: list[str]) -> None:
    parsed = parse_stick_table_declaration_arguments(lines)
    if not parsed:
        return
    for name in _STICK_TABLE_KEYWORDS:
        entry = keyword_docs.get(name)
        if entry is None:
            continue
        for variant in entry.variants:
            merge_argument_docs(variant, parsed)
