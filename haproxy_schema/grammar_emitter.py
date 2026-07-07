from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .grammar_build import build_tm_language
from .grammar_util import collect_cache_keywords, collect_directive_keywords, is_directive_token
from .io_util import write_text_lf
from .schema import HaproxySchema
from .tm_language_schema import TM_LANGUAGE_SCHEMA_FILENAME, build_tm_language_schema

# Backward-compatible aliases for tests and coverage tooling.
_is_directive_token = is_directive_token
_collect_cache_keywords = collect_cache_keywords
_collect_directive_keywords = collect_directive_keywords


def emit_tm_language(schema: HaproxySchema, template_path: Path | None = None) -> dict[str, Any]:
    """Emit a complete TextMate grammar from the schema."""
    del template_path
    return build_tm_language(schema)


def write_tm_language(
    schema: HaproxySchema,
    path: Path,
    template_path: Path | None = None,
) -> None:
    grammar = emit_tm_language(schema, template_path=template_path)
    write_text_lf(path, json.dumps(grammar, indent=2) + "\n")
    schema_path = path.parent / TM_LANGUAGE_SCHEMA_FILENAME
    write_text_lf(schema_path, json.dumps(build_tm_language_schema(), indent=2) + "\n")
