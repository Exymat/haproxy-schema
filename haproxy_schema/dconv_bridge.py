"""HAProxy configuration.txt keyword detection aligned with haproxy-dconv.

Vendors the keyword-line rules from haproxy-dconv/parser/keyword.py without
importing dconv's ``parser`` package (stdlib name collision).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re

# From haproxy-dconv/parser/keyword.py KeyWordParser.keywordPattern
_KEYWORD_PATTERN = re.compile(
    r"^("
    r"([a-z0-9\-\+_\.]*[a-z0-9\-\+_])"
    r"( [a-z0-9\-_]+)*"
    r")"
    r"(\([^ ]*\))?"
)

_PARAMETERS_TAIL = re.compile(
    r"^ +(/?(&lt;|<|\[|\{).*|(: [a-z0-9 +]+))?(\(deprecated\))?$"
)

DESCRIPTION_STOP_PREFIXES = (
    "May be used",
    "Arguments",
    "Argument ",
    "Example",
    "Examples",
    "See also",
    "Usable in:",
    "Available in",
    "This section",
    "Note to ",
)


@dataclass
class ArgumentValueDoc:
    name: str
    description: str = ""


@dataclass
class ArgumentParamDoc:
    parameter: str
    description: str = ""
    values: list[ArgumentValueDoc] = field(default_factory=list)


@dataclass
class KeywordDoc:
    name: str
    signatures: list[str] = field(default_factory=list)
    description: str = ""
    chapter: str = ""
    sections: list[str] = field(default_factory=list)
    contexts: list[str] = field(default_factory=list)
    arguments: list[ArgumentParamDoc] = field(default_factory=list)


def get_indent(line: str) -> int:
    indent = 0
    while indent < len(line) and line[indent] == " ":
        indent += 1
    return indent


_KEYWORD_NAME_RE = re.compile(r"^[a-z][a-z0-9_. +\-]*$", re.I)


def is_valid_keyword_name(name: str) -> bool:
    """Reject section underlines and other false positives from walk_keyword_docs."""
    cleaned = name.strip()
    if not cleaned or len(cleaned) > 120:
        return False
    if set(cleaned) <= {"-", "=", "_"}:
        return False
    if not _KEYWORD_NAME_RE.match(cleaned):
        return False
    if cleaned.lower().startswith(("this ", "the ", "see ", "note ", "using ")):
        return False
    return True


def match_dconv_keyword_line(line: str) -> tuple[str, str] | None:
    """Return (keyword_name, full_signature_line) if line is a dconv keyword header."""
    if not line or line.startswith(" "):
        return None
    if line.startswith("/*") or line.startswith("#"):
        return None
    if re.match(r"^\d+\.\d+\.", line.strip()):
        return None

    parsed = _KEYWORD_PATTERN.match(line)
    if not parsed:
        return None

    keyword = parsed.group(1)
    arg = parsed.group(4) or ""
    parameters = line[len(keyword) + len(arg) :]
    if parameters and not _PARAMETERS_TAIL.match(parameters):
        return None

    split_keyword = keyword.split()
    if len(split_keyword) > 4:
        return None

    return keyword, line.strip()


def _strip_paren_suffix(token: str) -> str:
    paren = token.find("(")
    if paren >= 0:
        return token[:paren]
    return token


def extract_keyword_name(signature: str) -> str:
    sig = re.sub(r"\s+\(deprecated\)$", "", signature.strip())
    tokens: list[str] = []
    for part in sig.split():
        if part.startswith("<") or part.startswith("[") or part.startswith("{"):
            break
        if part.endswith("*"):
            break
        tokens.append(_strip_paren_suffix(part))
    return " ".join(tokens) if tokens else _strip_paren_suffix(sig.split()[0])


_SECTIONS_MATRIX = ("defaults", "frontend", "listen", "backend")
_SECTIONS_HEADER_RE = re.compile(r"^\s*May be used in sections\s*:\s*(.+)$", re.I)
_CONTEXTS_HEADER_RE = re.compile(r"^\s*May be used in the following contexts\s*:\s*(.+)$", re.I)


def parse_contexts_blob(raw: str) -> list[str]:
    return [part.strip().lower() for part in raw.split(",") if part.strip()]


def is_skippable_metadata_line(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("Usable in:") or stripped.startswith("May be used in sections")


def extract_sections_from_keyword_block(lines: list[str], header_idx: int, end_idx: int) -> list[str]:
    """Parse the 'May be used in sections' matrix inside a keyword doc block."""
    idx = header_idx + 1
    while idx < end_idx:
        match = _SECTIONS_HEADER_RE.match(lines[idx])
        if match:
            header_parts = [part.strip().lower() for part in match.group(1).split("|")]
            marks_idx = idx + 1
            while marks_idx < end_idx and not lines[marks_idx].strip():
                marks_idx += 1
            if marks_idx >= end_idx:
                break
            marks = [part.strip().lower() for part in lines[marks_idx].split("|")]
            sections: list[str] = []
            for section, mark in zip(header_parts, marks):
                if section in _SECTIONS_MATRIX and mark.startswith("yes"):
                    sections.append(section)
            return sections
        idx += 1
    return []


def extract_contexts_from_keyword_block(lines: list[str], header_idx: int, end_idx: int) -> list[str]:
    idx = header_idx + 1
    while idx < end_idx:
        match = _CONTEXTS_HEADER_RE.match(lines[idx])
        if match:
            return parse_contexts_blob(match.group(1))
        idx += 1
    return []


def is_description_stop_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if is_skippable_metadata_line(line):
        return False
    return any(stripped.startswith(prefix) for prefix in DESCRIPTION_STOP_PREFIXES)


def extract_description_after_header(lines: list[str], header_idx: int) -> str:
    """First substantive indented paragraph after signature block."""
    idx = header_idx + 1
    while idx < len(lines):
        if match_dconv_keyword_line(lines[idx]):
            idx += 1
            continue
        if lines[idx].startswith("   "):
            idx += 1
            continue
        break

    parts: list[str] = []
    while idx < len(lines):
        line = lines[idx]
        if not line.strip():
            if parts:
                break
            idx += 1
            continue
        if not line.startswith("  ") or line.startswith("   "):
            break
        if is_skippable_metadata_line(line):
            idx += 1
            while idx < len(lines) and lines[idx].startswith(" ") and lines[idx].strip():
                idx += 1
            continue
        if is_description_stop_line(line):
            break
        parts.append(line.strip())
        idx += 1

    return " ".join(parts).strip()


def collect_signature_lines(lines: list[str], start_idx: int) -> tuple[list[str], int]:
    """Collect consecutive keyword header lines (alternate signatures)."""
    signatures: list[str] = []
    idx = start_idx
    while idx < len(lines):
        matched = match_dconv_keyword_line(lines[idx])
        if not matched and signatures:
            break
        if not matched:
            break
        sig = lines[idx].strip()
        if sig not in signatures:
            signatures.append(sig)
        idx += 1
    return signatures, idx


def _keyword_block_end(lines: list[str], header_idx: int) -> int:
    signatures, next_idx = collect_signature_lines(lines, header_idx)
    idx = next_idx
    while idx < len(lines):
        if match_dconv_keyword_line(lines[idx]):
            return idx
        if lines[idx].strip() and not lines[idx].startswith(" "):
            return idx
        idx += 1
    return len(lines)


def walk_keyword_docs(
    lines: list[str],
    start_idx: int,
    end_idx: int,
    chapter: str,
) -> dict[str, KeywordDoc]:
    from .argument_docs import extract_argument_docs

    docs: dict[str, KeywordDoc] = {}
    idx = start_idx
    while idx < end_idx:
        matched = match_dconv_keyword_line(lines[idx])
        if not matched:
            idx += 1
            continue

        signatures, next_idx = collect_signature_lines(lines, idx)
        names = list(
            dict.fromkeys(
                extract_keyword_name(sig)
                for sig in signatures
                if is_valid_keyword_name(extract_keyword_name(sig))
            )
        )
        if not names:
            idx = max(next_idx, idx + 1)
            continue
        block_end = min(_keyword_block_end(lines, idx), end_idx)
        description = extract_description_after_header(lines, idx)
        argument_docs = extract_argument_docs(lines, idx)
        block_sections = extract_sections_from_keyword_block(lines, idx, block_end)
        block_contexts = extract_contexts_from_keyword_block(lines, idx, block_end)

        for name in names:
            entry = docs.get(name)
            if entry is None:
                entry = KeywordDoc(name=name, chapter=chapter)
                docs[name] = entry
            for sig in signatures:
                if extract_keyword_name(sig) == name and sig not in entry.signatures:
                    entry.signatures.append(sig)
            if description and not entry.description:
                entry.description = description
            if argument_docs:
                merge_argument_docs(entry, argument_docs)
            for section in block_sections:
                if section not in entry.sections:
                    entry.sections.append(section)
            for context in block_contexts:
                if context not in entry.contexts:
                    entry.contexts.append(context)

        idx = max(next_idx, idx + 1)
    return docs


def merge_argument_docs(entry: KeywordDoc, parsed: list[ArgumentParamDoc]) -> None:
    existing_params = {p.parameter: p for p in entry.arguments}
    for param in parsed:
        if param.parameter in existing_params:
            target = existing_params[param.parameter]
            if param.description and not target.description:
                target.description = param.description
            seen = {v.name.lower() for v in target.values}
            for value in param.values:
                if value.name.lower() not in seen:
                    target.values.append(value)
                    seen.add(value.name.lower())
        else:
            entry.arguments.append(param)
            existing_params[param.parameter] = param
