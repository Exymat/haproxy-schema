from __future__ import annotations

import json
from importlib import resources
from typing import Any


def _resolve_refs(data: dict[str, Any]) -> dict[str, Any]:
    ref = data.get("$ref")
    if not isinstance(ref, str):
        return data
    ref_obj = resources.files(__package__).joinpath("schema_metadata", ref)
    return _resolve_refs(json.loads(ref_obj.read_text(encoding="utf-8")))


def load_schema_metadata(version: str) -> dict[str, Any]:
    """Load bundled schema-consumer metadata for a HAProxy version."""
    resource_name = f"{version}.json"
    try:
        ref = resources.files(__package__).joinpath("schema_metadata", resource_name)
        return _resolve_refs(json.loads(ref.read_text(encoding="utf-8")))
    except FileNotFoundError:
        return {}


def apply_schema_metadata(schema: Any, metadata: dict[str, Any]) -> None:
    schema.address_policies = metadata.get("address_policies", {})
    schema.sample_types = metadata.get("sample_types", [])
    schema.sample_casts = metadata.get("sample_casts", [])
    schema.symbols = metadata.get("symbols", {})
    schema.semantic_groups = metadata.get("semantic_groups", {})
    schema.validation_rules = metadata.get("validation_rules", {})
