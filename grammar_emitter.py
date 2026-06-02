from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

from .schema import HaproxySchema

_TEMPLATE_NAME = "haproxy.tmLanguage.json"


def _escape_regex(word: str) -> str:
    return re.escape(word)


def _alt_pattern(words: list[str], limit: int = 300) -> str:
    chunk = sorted(set(words), key=len, reverse=True)[:limit]
    if not chunk:
        return "(?!)never-match"
    return "(?:" + "|".join(_escape_regex(w) for w in chunk) + ")"


def emit_tm_language(schema: HaproxySchema, template_path: Path | None = None) -> dict[str, Any]:
    groups = schema.keyword_groups
    sections = sorted(schema.sections.keys())

    if not template_path or not template_path.is_file():
        from .grammar_emitter_minimal import emit_tm_language_minimal

        return emit_tm_language_minimal(schema)

    grammar = copy.deepcopy(json.loads(template_path.read_text(encoding="utf-8")))
    grammar["name"] = f"HAProxy {schema.version}"
    repo = grammar.get("repository", {})
    sec_pat = _alt_pattern(sections)

    for entry in repo.get("sections", {}).get("patterns", []):
        if "match" not in entry:
            continue
        entry["match"] = re.sub(
            r"\((?:global\|defaults\|listen\|frontend\|backend\|peers\|userlist\|resolvers\|mailers\|program\|http-errors\|ring\|cache\|crt-list\|crt-store\|traces\|acme)\)",
            f"({sec_pat})",
            entry["match"],
        )
        entry["match"] = re.sub(
            r"\(listen\|frontend\|backend\|peers\|userlist\|resolvers\|mailers\|program\|http-errors\|ring\|cache\|crt-list\|crt-store\|traces\|acme\)",
            f"({sec_pat})",
            entry["match"],
        )

    fetches = _alt_pattern(groups.get("sample_fetches", []), limit=500)
    for entry in repo.get("sample-fetches", {}).get("patterns", []):
        match = entry.get("match", "")
        if "match" in entry and len(match) > 80 and "hdr" in match:
            entry["match"] = re.sub(
                r"\\b\([^)]{40,}\)\\b",
                f"\\\\b({fetches})\\\\b",
                match,
                count=1,
            )

    return grammar


def write_tm_language(
    schema: HaproxySchema,
    path: Path,
    template_path: Path | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if template_path is None:
        template_path = path.parent / _TEMPLATE_NAME
    grammar = emit_tm_language(schema, template_path=template_path)
    path.write_text(json.dumps(grammar, indent=2) + "\n", encoding="utf-8")
