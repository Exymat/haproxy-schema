from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .schema import HaproxySchema

SECTION_HEADERS = {
    "global",
    "defaults",
    "frontend",
    "backend",
    "listen",
    "peers",
    "userlist",
    "resolvers",
    "mailers",
    "program",
    "http-errors",
    "ring",
    "cache",
    "crt-list",
    "crt-store",
    "traces",
    "acme",
}

PREFIX_FAMILIES = [
    "stats",
    "timeout",
    "tcp-check",
    "http-check",
    "capture",
    "tcp-request",
    "tcp-response",
]


@dataclass
class ParsedToken:
    text: str
    start: int
    end: int


@dataclass
class ParsedLine:
    line: int
    section: str | None
    tokens: list[ParsedToken]
    is_section_header: bool


@dataclass
class ValidationIssue:
    line: int
    code: str
    message: str
    keyword: str = ""


@dataclass
class ValidationResult:
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def unknown_keyword_issues(self) -> list[ValidationIssue]:
        return [issue for issue in self.issues if issue.code == "unknown-keyword"]


def _tokenize_line(line: str) -> list[ParsedToken]:
    tokens: list[ParsedToken] = []
    i = 0
    token_start = -1
    quote: str | None = None
    escaped = False

    def flush(end: int) -> None:
        nonlocal token_start
        if token_start >= 0 and end > token_start:
            tokens.append(
                ParsedToken(text=line[token_start:end], start=token_start, end=end)
            )
            token_start = -1

    while i < len(line):
        ch = line[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch == "#" and token_start < 0:
            break
        if ch in {"'", '"'}:
            if token_start < 0:
                token_start = i
            quote = ch
            i += 1
            continue
        if ch.isspace():
            flush(i)
            i += 1
            continue
        if token_start < 0:
            token_start = i
        i += 1
    flush(i)
    return tokens


def parse_config_text(content: str) -> list[ParsedLine]:
    out: list[ParsedLine] = []
    current_section: str | None = None
    for line_no, text in enumerate(content.splitlines()):
        tokens = _tokenize_line(text)
        is_section_header = False
        if tokens:
            first = tokens[0].text.lower()
            if first in SECTION_HEADERS:
                current_section = first
                is_section_header = True
        out.append(
            ParsedLine(
                line=line_no,
                section=current_section,
                tokens=tokens,
                is_section_header=is_section_header,
            )
        )
    return out


def _is_likely_value(token: str) -> bool:
    if not token:
        return True
    if token.startswith("<") and token.endswith(">"):
        return True
    if token[0] in {'"', "'"}:
        return True
    if token.startswith("{") or token.startswith("%[") or token.startswith("("):
        return True
    if token[0].isdigit():
        return True
    if any(ch in token for ch in (":", "/", "=")):
        return True
    if token in {"if", "unless"}:
        return True
    return False


def _is_directive_part(token: str) -> bool:
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9_.-]*$", token))


def _join_tokens(tokens: list[ParsedToken], start: int, end: int) -> str:
    return " ".join(tok.text.lower() for tok in tokens[start : end + 1])


def _section_allowed(schema: HaproxySchema, section: str | None) -> set[str]:
    if not section:
        return set()
    sec = schema.sections.get(section)
    allowed = {k.lower() for k in sec.keywords} if sec else set()
    for name, keyword in schema.keywords.items():
        if section in keyword.sections:
            allowed.add(name.lower())
    return allowed


def _resolve_longest_match(
    line: ParsedLine, allowed: set[str], max_parts: int = 4
) -> tuple[str, bool]:
    tokens = line.tokens
    if not tokens:
        return "", False
    limit = min(len(tokens), max_parts)
    for end in range(limit - 1, -1, -1):
        keyword = _join_tokens(tokens, 0, end)
        hyphen = "-".join(tok.text.lower() for tok in tokens[: end + 1])
        if keyword in allowed or (end == 1 and hyphen in allowed):
            return keyword if keyword in allowed else hyphen, True
    end = 0
    while end < len(tokens) and end < max_parts:
        if end > 0 and _is_likely_value(tokens[end].text):
            break
        if not _is_directive_part(tokens[end].text):
            break
        end += 1
    if end == 0:
        end = 1
    else:
        end -= 1
    return _join_tokens(tokens, 0, end), False


def _is_option_line(line: ParsedLine) -> bool:
    if not line.tokens:
        return False
    t0 = line.tokens[0].text.lower()
    t1 = line.tokens[1].text.lower() if len(line.tokens) > 1 else ""
    return t0 == "option" or (t0 == "no" and t1 == "option")


def _option_allowed(allowed: set[str]) -> bool:
    if "option" in allowed:
        return True
    return any(k.startswith("option ") or k.startswith("no option") for k in allowed)


def _no_prefix_keywords(schema: HaproxySchema) -> set[str]:
    return {k.lower() for k in schema.tokens.get("no_prefix_keywords", [])}


def _is_no_prefix_line(
    line: ParsedLine, allowed: set[str], no_prefix: set[str]
) -> bool:
    if len(line.tokens) < 2:
        return False
    if line.tokens[0].text.lower() not in {"no", "default"}:
        return False
    keyword, matched = _resolve_longest_match(
        ParsedLine(
            line=line.line,
            section=line.section,
            tokens=line.tokens[1:],
            is_section_header=False,
        ),
        allowed,
    )
    return matched and keyword.lower() in no_prefix


def validate_config(content: str, schema: HaproxySchema) -> ValidationResult:
    result = ValidationResult()
    macros = {m.lower() for m in schema.tokens.get("macros", [])}
    no_prefix = _no_prefix_keywords(schema)

    for line in parse_config_text(content):
        if not line.tokens or line.is_section_header:
            continue
        if line.tokens[0].text.lower() in macros:
            continue

        allowed = _section_allowed(schema, line.section)
        if _is_option_line(line) and _option_allowed(allowed):
            continue
        if _is_no_prefix_line(line, allowed, no_prefix):
            continue

        keyword, matched = _resolve_longest_match(line, allowed)
        if matched:
            continue

        t0 = line.tokens[0].text.lower()
        if t0 in PREFIX_FAMILIES:
            needle = f"{t0} "
            subs = {k[len(needle) :] for k in allowed if k.startswith(needle)}
            if subs:
                for end in range(min(len(line.tokens) - 1, 3), 0, -1):
                    if _join_tokens(line.tokens, 1, end) in subs:
                        matched = True
                        break
        if matched:
            continue

        other = schema.keywords.get(keyword.lower())
        if other and line.section and line.section not in other.sections:
            continue

        result.issues.append(
            ValidationIssue(
                line=line.line,
                code="unknown-keyword",
                message=f"Unknown keyword '{keyword}' in section '{line.section or 'none'}'",
                keyword=keyword,
            )
        )
    return result


def validate_config_file(path: Path, schema: HaproxySchema) -> ValidationResult:
    return validate_config(path.read_text(encoding="utf-8", errors="replace"), schema)
