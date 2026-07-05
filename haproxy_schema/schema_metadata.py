from __future__ import annotations

import copy
import json
from importlib import resources
from typing import Any


CURATED_CATEGORIES = {"editor", "derived_hint", "curated_runtime"}


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _resolve_refs(data: dict[str, Any]) -> dict[str, Any]:
    ref = data.get("$ref")
    if not isinstance(ref, str):
        return data
    ref_obj = resources.files(__package__).joinpath("curated_metadata", ref)
    resolved = _resolve_refs(json.loads(ref_obj.read_text(encoding="utf-8")))
    extra = {key: value for key, value in data.items() if key != "$ref"}
    return _deep_merge(resolved, extra)


def load_curated_metadata(version: str) -> dict[str, Any]:
    """Load explicitly curated schema metadata overlays for a HAProxy version."""
    resource_name = f"{version}.json"
    try:
        ref = resources.files(__package__).joinpath("curated_metadata", resource_name)
        return _resolve_refs(json.loads(ref.read_text(encoding="utf-8")))
    except FileNotFoundError:
        return {}


def iter_curated_entries(curated: dict[str, Any]) -> list[tuple[str, str, Any, str, bool]]:
    """Return (field path, category, value, reason, accepted) entries from curated overlay JSON."""
    entries: list[tuple[str, str, Any, str, bool]] = []
    for field, payload in curated.items():
        if not isinstance(payload, dict):
            raise ValueError(f"curated metadata field {field!r} must be an object")
        category = payload.get("category")
        if category not in CURATED_CATEGORIES:
            raise ValueError(f"curated metadata field {field!r} has invalid category {category!r}")
        if "value" not in payload:
            raise ValueError(f"curated metadata field {field!r} is missing value")
        reason = payload.get("reason", "")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"curated metadata field {field!r} is missing reason")
        accepted = bool(payload.get("accepted", False))
        if category == "curated_runtime" and not accepted:
            raise ValueError(f"curated runtime metadata field {field!r} must be explicitly accepted")
        entries.append((field, category, payload["value"], reason, accepted))
    return entries


def apply_schema_metadata(schema: Any, metadata: dict[str, Any]) -> None:
    schema.address_policies = metadata.get("address_policies", {})
    schema.sample_types = metadata.get("sample_types", [])
    schema.sample_casts = metadata.get("sample_casts", [])
    schema.symbols = metadata.get("symbols", {})
    schema.semantic_groups = metadata.get("semantic_groups", {})
    schema.validation_rules = metadata.get("validation_rules", {})
