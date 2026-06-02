"""Fallback minimal grammar when no template is available."""

from __future__ import annotations

from typing import Any

from .schema import HaproxySchema


def emit_tm_language_minimal(schema: HaproxySchema) -> dict[str, Any]:
    return {
        "$schema": "https://raw.githubusercontent.com/martinring/tmlanguage/master/tmlanguage.json",
        "name": f"HAProxy {schema.version}",
        "scopeName": "source.haproxy",
        "patterns": [{"include": "#comments"}],
        "repository": {
            "comments": {
                "patterns": [{"name": "comment.line.number-sign.haproxy", "match": "#.*$"}]
            }
        },
    }
