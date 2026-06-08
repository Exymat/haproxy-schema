from __future__ import annotations

import re

from .schema import HaproxySchema

_DIRECTIVE_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]*$", re.IGNORECASE)

_ACTION_GROUP_KEYS = (
    "http_request_actions",
    "http_response_actions",
    "http_after_response_actions",
    "tcp_request_actions",
    "tcp_response_actions",
    "quic_initial_actions",
)


def is_directive_token(word: str) -> bool:
    if not word or len(word) > 64:
        return False
    if any(ch in word for ch in " \t:()|+<>,\"'"):
        return False
    return bool(_DIRECTIVE_NAME_RE.match(word))


def escape_regex(word: str) -> str:
    return re.escape(word)


def canonical_pattern_words(words: list[str] | set[str], limit: int | None = None) -> list[str]:
    ordered = sorted(set(words), key=lambda word: (-len(word), word))
    if limit is None:
        return ordered
    return ordered[:limit]


def alt_pattern(words: list[str], limit: int = 300) -> str:
    chunk = canonical_pattern_words(words, limit=limit)
    if not chunk:
        return "(?!)never-match"
    return "(?:" + "|".join(escape_regex(w) for w in chunk) + ")"


def action_words(schema: HaproxySchema) -> set[str]:
    words: set[str] = set()
    for key in _ACTION_GROUP_KEYS:
        words.update(schema.keyword_groups.get(key, []))
    return {w for w in words if is_directive_token(w)}


def collect_cache_keywords(schema: HaproxySchema) -> list[str]:
    words: set[str] = set()
    for name, keyword in schema.keywords.items():
        if not is_directive_token(name):
            continue
        if "cache" in keyword.sections:
            words.add(name)
    return canonical_pattern_words(words)


def collect_directive_keywords(schema: HaproxySchema) -> list[str]:
    skip = action_words(schema)
    skip.update(schema.keyword_groups.get("bind_options", []))
    skip.update(schema.keyword_groups.get("server_options", []))
    skip.update(schema.keyword_groups.get("options", []))
    skip.update(schema.keyword_groups.get("acl_criteria", []))

    words: set[str] = set()
    for name in schema.keywords:
        if not is_directive_token(name) or " " in name or name in skip:
            continue
        words.add(name)
    for rule in schema.statement_rules:
        if is_directive_token(rule.keyword):
            words.add(rule.keyword)

    filtered: list[str] = []
    sorted_words = canonical_pattern_words(words)
    for word in sorted_words:
        if any(
            other != word and len(other) > len(word) and other.startswith(f"{word}-")
            for other in words
        ):
            continue
        filtered.append(word)
    return canonical_pattern_words(filtered)
