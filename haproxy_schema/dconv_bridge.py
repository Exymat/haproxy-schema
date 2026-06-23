"""HAProxy configuration.txt keyword detection aligned with haproxy-dconv.

Vendors the keyword-line rules from haproxy-dconv/parser/keyword.py without
importing dconv's ``parser`` package (stdlib name collision).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re

from .example_docs import ExampleDoc, extract_example_blocks

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
class KeywordVariantDoc:
    """One documentation occurrence of a keyword in a specific configuration.txt chapter."""

    chapter: str = ""
    sections: list[str] = field(default_factory=list)
    signatures: list[str] = field(default_factory=list)
    description: str = ""
    examples: list[ExampleDoc] = field(default_factory=list)
    contexts: list[str] = field(default_factory=list)
    arguments: list[ArgumentParamDoc] = field(default_factory=list)


@dataclass
class KeywordDoc:
    name: str
    variants: list[KeywordVariantDoc] = field(default_factory=list)

    def variants_for(self, chapter: str) -> list[KeywordVariantDoc]:
        return [variant for variant in self.variants if variant.chapter == chapter]

    def variant_for(
        self,
        chapter: str,
        *,
        signatures: list[str] | None = None,
        sections: list[str] | None = None,
    ) -> KeywordVariantDoc:
        chapter_variants = self.variants_for(chapter)
        if chapter_variants:
            wanted_signatures = set(signatures or [])
            wanted_sections = set(sections or [])
            if wanted_signatures or wanted_sections:
                for variant in chapter_variants:
                    if wanted_signatures and set(variant.signatures) != wanted_signatures:
                        continue
                    if wanted_sections and set(variant.sections) != wanted_sections:
                        continue
                    return variant
            elif len(chapter_variants) == 1:
                return chapter_variants[0]
        variant = KeywordVariantDoc(chapter=chapter)
        if signatures:
            variant.signatures.extend(signatures)
        if sections:
            variant.sections.extend(sections)
        self.variants.append(variant)
        return variant

    @property
    def chapter(self) -> str:
        if len(self.variants) == 1:
            return self.variants[0].chapter
        for preferred in ("4.2", "3.1", "3.2", "3.3"):
            for variant in self.variants:
                if variant.chapter == preferred:
                    return preferred
        return self.variants[0].chapter if self.variants else ""

    @chapter.setter
    def chapter(self, value: str) -> None:
        if not self.variants:
            self.variants.append(KeywordVariantDoc(chapter=value))
            return
        if len(self.variants) == 1:
            self.variants[0].chapter = value

    @property
    def sections(self) -> list[str]:
        out: list[str] = []
        for variant in self.variants:
            for section in variant.sections:
                if section not in out:
                    out.append(section)
        return out

    @property
    def signatures(self) -> list[str]:
        out: list[str] = []
        for variant in self.variants:
            for signature in variant.signatures:
                if signature not in out:
                    out.append(signature)
        return out

    @property
    def description(self) -> str:
        for preferred in ("4.2",):
            for variant in self.variants:
                if variant.chapter == preferred and variant.description:
                    return variant.description
        for variant in self.variants:
            if variant.description:
                return variant.description
        return ""

    @property
    def contexts(self) -> list[str]:
        out: list[str] = []
        for variant in self.variants:
            for context in variant.contexts:
                if context not in out:
                    out.append(context)
        return out

    @property
    def arguments(self) -> list[ArgumentParamDoc]:
        for preferred in ("4.2",):
            for variant in self.variants:
                if variant.chapter == preferred and variant.arguments:
                    return variant.arguments
        for variant in self.variants:
            if variant.arguments:
                return variant.arguments
        return []

    @property
    def examples(self) -> list[ExampleDoc]:
        for preferred in ("4.2",):
            for variant in self.variants:
                if variant.chapter == preferred and variant.examples:
                    return variant.examples
        for variant in self.variants:
            if variant.examples:
                return variant.examples
        return []


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


def _is_signature_parameter_token(token: str) -> bool:
    stripped = token.strip()
    if not stripped:
        return False
    if stripped[0] in "<[{":
        return True
    if len(stripped) >= 2 and stripped[0] in "/:" and stripped[1] in "<[{":
        return True
    return False


def extract_keyword_name(signature: str) -> str:
    sig = re.sub(r"\s+\(deprecated\)$", "", signature.strip())
    tokens: list[str] = []
    for part in sig.split():
        if _is_signature_parameter_token(part):
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


_SIGNATURE_CONTINUATION_RE = re.compile(r"^[\[<{]")
_SIGNATURE_SYNTAX_RE = re.compile(r"[<|\[\]{}]|]\*|\]\s*\*")


def _looks_like_signature_fragment(stripped: str) -> bool:
    if _SIGNATURE_CONTINUATION_RE.match(stripped):
        return True
    if _SIGNATURE_SYNTAX_RE.search(stripped):
        return True
    return False


def is_signature_continuation_line(line: str) -> bool:
    """True for indented signature fragments split across doc lines (e.g. log facility tail)."""
    if get_indent(line) < 4:
        return False
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith("#"):
        return False
    if is_description_stop_line(line):
        return False
    return _looks_like_signature_fragment(stripped)


def extract_description_after_header(lines: list[str], header_idx: int) -> str:
    """Collect prose paragraphs after the signature block, skipping metadata tables."""
    idx = header_idx + 1
    while idx < len(lines):
        if match_dconv_keyword_line(lines[idx]):
            idx += 1
            continue
        if lines[idx].startswith("   "):
            idx += 1
            continue
        break

    paragraphs: list[str] = []
    current: list[str] = []
    while idx < len(lines):
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
        if get_indent(line) < 2:
            break
        stripped = line.strip()
        if get_indent(line) >= 4 and _SIGNATURE_CONTINUATION_RE.match(stripped):
            break
        if is_skippable_metadata_line(line):
            if current:
                paragraphs.append(" ".join(current).strip())
                current = []
            idx += 1
            while idx < len(lines) and lines[idx].startswith(" ") and lines[idx].strip():
                idx += 1
            continue
        if is_description_stop_line(line):
            break
        current.append(line.strip())
        idx += 1

    if current:
        paragraphs.append(" ".join(current).strip())

    return "\n\n".join(paragraph for paragraph in paragraphs if paragraph).strip()


def _append_signature_continuations(lines: list[str], signatures: list[str], idx: int) -> int:
    while idx < len(lines) and is_signature_continuation_line(lines[idx]):
        signatures[-1] = f"{signatures[-1]} {lines[idx].strip()}"
        idx += 1
    return idx


def collect_signature_lines(lines: list[str], start_idx: int) -> tuple[list[str], int]:
    """Collect consecutive keyword header lines (alternate signatures)."""
    signatures: list[str] = []
    idx = start_idx
    while idx < len(lines):
        matched = match_dconv_keyword_line(lines[idx])
        if not matched:
            if signatures and is_signature_continuation_line(lines[idx]):
                idx = _append_signature_continuations(lines, signatures, idx)
                continue
            break
        sig = lines[idx].strip()
        if sig not in signatures:
            signatures.append(sig)
        idx += 1
        idx = _append_signature_continuations(lines, signatures, idx)
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
        example_docs = extract_example_blocks(lines, idx, block_end)
        block_sections = extract_sections_from_keyword_block(lines, idx, block_end)
        block_contexts = extract_contexts_from_keyword_block(lines, idx, block_end)

        for name in names:
            entry = docs.get(name)
            if entry is None:
                entry = KeywordDoc(name=name)
                docs[name] = entry
            variant = entry.variant_for(
                chapter,
                signatures=[sig for sig in signatures if extract_keyword_name(sig) == name],
                sections=block_sections,
            )
            for sig in signatures:
                if extract_keyword_name(sig) == name and sig not in variant.signatures:
                    variant.signatures.append(sig)
            if description and not variant.description:
                variant.description = description
            if example_docs and not variant.examples:
                variant.examples = list(example_docs)
            if argument_docs:
                merge_argument_docs(variant, argument_docs)
            for section in block_sections:
                if section not in variant.sections:
                    variant.sections.append(section)
            for context in block_contexts:
                if context not in variant.contexts:
                    variant.contexts.append(context)

        idx = max(next_idx, idx + 1)
    return docs


def merge_argument_docs(entry: KeywordDoc | KeywordVariantDoc, parsed: list[ArgumentParamDoc]) -> None:
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
