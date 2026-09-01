from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .grammar_emitter import emit_tm_language
from .grammar_util import collect_cache_keywords, collect_directive_keywords, is_directive_token
from .schema import HaproxySchema

_DIRECTIVE_SCOPE = "keyword.other.directive.haproxy"
_OPTION_SCOPE = "keyword.other.option.haproxy"
_SECTION_SCOPE = "entity.name.type.section.haproxy"
_PROXY_SCOPE = "entity.name.type.proxy.haproxy"

# Legacy hand-maintained rules that may duplicate schema-directives (audit only).
# Optional hand-maintained overrides (empty when grammar is fully generated).
_LEGACY_REPO_KEYS: tuple[str, ...] = ()


def _unescape_regex_literal(word: str) -> str:
    return word.replace("\\-", "-").replace("\\.", ".").replace("\\_", "_")


def _extract_schema_directive_alternation(pattern: str) -> set[str]:
    """Read words from \\b(?:a|b|c)\\b produced by grammar_emitter."""
    for regex in (
        r"\\b\(\?:\(\?:([^)]*)\)\)",
        r"\\b\(\?:([^)]*)\)",
        r"\\b__SCHEMA_DIRECTIVES__",
    ):
        found = re.search(regex, pattern)
        if not found:
            continue
        if found.lastindex:
            return {_unescape_regex_literal(part) for part in found.group(1).split("|") if part}
    return set()


def _extract_repo_literals(repo: dict[str, Any], repo_key: str) -> set[str]:
    words: set[str] = set()
    for entry in repo.get(repo_key, {}).get("patterns", []):
        match = entry.get("match", "")
        if not match:
            continue
        if repo_key in ("schema-directives", "cache-keywords"):
            words.update(_extract_schema_directive_alternation(match))
            continue
        for group in re.findall(r"\(\?:([^)]*)\)", match):
            for part in group.split("|"):
                part = part.strip()
                if part and re.fullmatch(r"(?:[\\w.\\-]+|\\\\-)+", part):
                    words.add(_unescape_regex_literal(part))
    return words


def _repo_patterns_have_hyphen_guard(repo: dict[str, Any], repo_key: str) -> bool:
    patterns = repo.get(repo_key, {}).get("patterns", [])
    return bool(patterns) and all("(?!-)" in entry.get("match", "") for entry in patterns)


def _prefix_conflicts(words: set[str]) -> list[tuple[str, str]]:
    conflicts: list[tuple[str, str]] = []
    ordered = sorted(words, key=len)
    for i, short in enumerate(ordered):
        for long in ordered[i + 1 :]:
            if long.startswith(f"{short}-"):
                conflicts.append((short, long))
    return conflicts


@dataclass
class GrammarCoverageReport:
    version: str
    schema_directive_count: int = 0
    grammar_schema_directive_count: int = 0
    cache_keyword_count: int = 0
    grammar_cache_keyword_count: int = 0
    missing_in_grammar: list[str] = field(default_factory=list)
    extra_in_grammar: list[str] = field(default_factory=list)
    missing_cache_in_grammar: list[str] = field(default_factory=list)
    prefix_conflicts_in_grammar: list[tuple[str, str]] = field(default_factory=list)
    legacy_only_not_in_schema: list[str] = field(default_factory=list)
    legacy_hyphen_when_schema_underscore: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "schema_directive_count": self.schema_directive_count,
            "grammar_schema_directive_count": self.grammar_schema_directive_count,
            "cache_keyword_count": self.cache_keyword_count,
            "grammar_cache_keyword_count": self.grammar_cache_keyword_count,
            "missing_in_grammar": self.missing_in_grammar,
            "extra_in_grammar": self.extra_in_grammar,
            "missing_cache_in_grammar": self.missing_cache_in_grammar,
            "prefix_conflicts_in_grammar": self.prefix_conflicts_in_grammar,
            "legacy_only_not_in_schema": self.legacy_only_not_in_schema,
            "legacy_hyphen_when_schema_underscore": self.legacy_hyphen_when_schema_underscore,
        }

    @property
    def ok(self) -> bool:
        return (
            not self.missing_in_grammar
            and not self.missing_cache_in_grammar
            and not self.prefix_conflicts_in_grammar
            and not self.legacy_hyphen_when_schema_underscore
        )


def build_grammar_coverage_report(
    schema: HaproxySchema,
    grammar: dict[str, Any],
) -> GrammarCoverageReport:
    expected = set(collect_directive_keywords(schema))
    repo = grammar.get("repository", {})
    in_grammar = _extract_repo_literals(repo, "schema-directives")

    expected_cache = set(collect_cache_keywords(schema))
    in_cache = _extract_repo_literals(repo, "cache-keywords")

    legacy: set[str] = set()
    for key in _LEGACY_REPO_KEYS:
        legacy.update(_extract_repo_literals(repo, key))

    schema_keys = {name for name in schema.keywords if is_directive_token(name)}
    legacy_stale = sorted(legacy - schema_keys - expected - expected_cache)
    legacy_hyphen = sorted(
        word
        for word in legacy
        if "-" in word and word.replace("-", "_") in schema_keys and word not in schema_keys
    )

    prefix_conflicts = (
        []
        if _repo_patterns_have_hyphen_guard(repo, "schema-directives")
        and _repo_patterns_have_hyphen_guard(repo, "cache-keywords")
        else _prefix_conflicts(in_grammar | in_cache)
    )

    return GrammarCoverageReport(
        version=schema.version,
        schema_directive_count=len(expected),
        grammar_schema_directive_count=len(in_grammar),
        cache_keyword_count=len(expected_cache),
        grammar_cache_keyword_count=len(in_cache),
        missing_in_grammar=sorted(expected - in_grammar),
        extra_in_grammar=sorted(in_grammar - expected),
        missing_cache_in_grammar=sorted(expected_cache - in_cache),
        prefix_conflicts_in_grammar=prefix_conflicts,
        legacy_only_not_in_schema=legacy_stale[:50],
        legacy_hyphen_when_schema_underscore=legacy_hyphen,
    )


def load_grammar(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def report_from_paths(
    schema_path: Path,
    grammar_path: Path,
    template_path: Path | None = None,
    *,
    strict_grammar: bool = False,
) -> GrammarCoverageReport:
    del template_path
    schema = HaproxySchema.from_json(schema_path.read_text(encoding="utf-8"))
    if grammar_path.is_file():
        try:
            grammar = load_grammar(grammar_path)
            if grammar.get("repository", {}).get("schema-directives"):
                return build_grammar_coverage_report(schema, grammar)
            if strict_grammar:
                raise ValueError(f"missing repository.schema-directives in {grammar_path}")
        except (json.JSONDecodeError, OSError):
            if strict_grammar:
                raise
    elif strict_grammar:
        raise FileNotFoundError(f"grammar file not found: {grammar_path}")
    grammar = emit_tm_language(schema)
    return build_grammar_coverage_report(schema, grammar)
