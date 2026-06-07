"""Fallback minimal grammar for lightweight local use."""

from __future__ import annotations

from typing import Any

from .schema import HaproxySchema
from .tm_language_schema import TM_LANGUAGE_SCHEMA_REF


def emit_tm_language_minimal(schema: HaproxySchema) -> dict[str, Any]:
    return {
        "$schema": TM_LANGUAGE_SCHEMA_REF,
        "name": f"HAProxy {schema.version}",
        "scopeName": "source.haproxy",
        "patterns": [{"include": "#comments"}],
        "repository": {
            "comments": {
                "patterns": [{"name": "comment.line.number-sign.haproxy", "match": "#.*$"}]
            }
        },
    }
