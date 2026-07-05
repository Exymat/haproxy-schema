from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .schema import HaproxySchema
from .schema_metadata import apply_schema_metadata, iter_curated_entries, load_curated_metadata
from .source_metadata_extractors import (
    extract_address_policies,
    extract_cookie_modes,
    extract_http_send_name_header_rule,
    extract_mysql_check_rule,
    extract_sample_casts,
    extract_sample_min_args,
    extract_sample_types,
)


REQUIRED_METADATA_FIELDS = (
    "address_policies",
    "sample_types",
    "sample_casts",
    "symbols",
    "semantic_groups",
    "validation_rules",
)


@dataclass
class MetadataBuild:
    metadata: dict[str, Any]
    provenance: dict[str, Any] = field(default_factory=dict)
    curated_runtime: dict[str, Any] = field(default_factory=dict)

    def report(self, version: str) -> dict[str, Any]:
        missing = [field for field in REQUIRED_METADATA_FIELDS if not self.metadata.get(field)]
        return {
            "version": version,
            "ok": not missing,
            "missing_required_fields": missing,
            "provenance": self.provenance,
            "curated_runtime": self.curated_runtime,
        }


def infer_haproxy_root(version: str, doc_path: Path | None = None) -> Path | None:
    if doc_path is not None:
        doc_path = doc_path.resolve()
        if doc_path.name == "configuration.txt" and doc_path.parent.name == "doc":
            return doc_path.parent.parent
    package_root = Path(__file__).resolve().parents[1]
    monorepo_root = package_root.parent
    candidate = monorepo_root / "haproxy_git" / f"haproxy-{version}"
    return candidate if candidate.is_dir() else None


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _put_path(target: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cursor = target
    for part in parts[:-1]:
        next_value = cursor.setdefault(part, {})
        if not isinstance(next_value, dict):
            raise ValueError(f"cannot apply curated metadata path {path!r}")
        cursor = next_value
    cursor[parts[-1]] = copy.deepcopy(value)


def _mode_values(schema: HaproxySchema) -> list[str]:
    kw = schema.keywords.get("mode")
    if not kw:
        return []
    values: set[str] = set()
    for arg in kw.arguments:
        values.update(value.name for value in arg.values if value.name)
    for variant in kw.variants:
        for arg in variant.arguments:
            values.update(value.name for value in arg.values if value.name)
    if values:
        return sorted(values)
    signatures = " ".join(kw.signatures)
    return sorted(set(value for value in ("tcp", "http", "log", "spop", "haterm") if value in signatures))


def _derive_symbols(schema: HaproxySchema) -> tuple[dict[str, Any], dict[str, Any]]:
    sections = set(schema.sections)
    named_section_order = ("frontend", "backend", "listen", "defaults", "peers", "userlist")
    section_kind_order = (
        ("frontend", "proxy-section"),
        ("backend", "proxy-section"),
        ("listen", "proxy-section"),
        ("defaults", "defaults-profile"),
        ("cache", "cache"),
        ("userlist", "userlist"),
        ("resolvers", "resolvers"),
        ("peers", "peers"),
    )
    section_definition_kinds = {
        section: kind for section, kind in section_kind_order if section in sections
    }
    proxy_sections = [section for section in ("frontend", "backend", "listen") if section in sections]
    entry_point_sections = [
        section
        for section in ("frontend", "listen")
        if section in sections and "bind" in schema.sections[section].keywords
    ]
    definition_kinds = {
        rule.definition_kind
        for rule in schema.statement_rules
        if rule.definition_kind and rule.definition_kind not in {"proxy-section", "defaults-profile"}
    }
    symbols = {
        "proxy_sections": proxy_sections,
        "entry_point_sections": entry_point_sections,
        "named_sections": [section for section in named_section_order if section in sections],
        "bind_detect_keywords": sorted(
            keyword for keyword in ("bind", "bind-process") if keyword == "bind-process" or keyword in schema.keywords
        ),
        "runtime_modes": _mode_values(schema),
        "section_definition_kinds": section_definition_kinds,
        "scoped_symbol_kinds": sorted(definition_kinds),
    }
    return symbols, {"origin": "derived", "rule": "sections, statement_rules, and mode docs"}


def _derive_semantic_groups(schema: HaproxySchema) -> tuple[dict[str, Any], dict[str, Any]]:
    action_groups = sorted(name for name in schema.keyword_groups if name.endswith("_actions"))
    completion_map: dict[str, str] = {}
    for group in action_groups:
        if group == "quic_initial_actions":
            continue
        kind = group.removesuffix("_actions").replace("_", "-")
        completion_map[kind] = group
    line_option_groups: dict[str, str] = {}
    for keyword in schema.keywords.values():
        for item in keyword.line_option_semantics:
            line_option_groups[item.parent_kind] = item.option_group
    use_service_rule_kinds = [
        group.removesuffix("_actions").replace("_", "-")
        for group in action_groups
        if "use-service" in schema.keyword_groups.get(group, [])
    ]
    groups = {
        "action_groups": action_groups,
        "deprecated_action_groups": action_groups,
        "completion_kind_to_action_group": completion_map,
        "line_option_group_for_kind": dict(sorted(line_option_groups.items())),
        "sample_expression_group_for_kind": {
            "expression-fetch": "sample_fetches",
            "expression-converter": "sample_converters",
        },
        "acl_criterion_groups": [
            group for group in ("acl_criteria", "sample_fetches") if group in schema.keyword_groups
        ],
        "log_format_groups": {"flags": "logformat_flags", "aliases": "logformat_aliases"},
        "common_language_groups": {
            group: group
            for group in ("options", "services", "filters")
            if group in schema.keyword_groups
        },
        "use_service": {
            "rule_kinds": sorted(use_service_rule_kinds),
            "action": "use-service",
            "service_group": "services",
            "allow_prefixes": [],
        },
    }
    return groups, {"origin": "derived", "rule": "keyword_groups and line_option_semantics"}


def _derive_validation_rules(schema: HaproxySchema) -> tuple[dict[str, Any], dict[str, Any]]:
    rule_keywords = {rule.keyword for rule in schema.statement_rules}
    skip_candidates = (
        "bind",
        "server",
        "acl",
        "option",
        "stats",
        "http-request",
        "http-response",
        "tcp-request",
        "tcp-response",
        "http-after-response",
        "http-check",
        "tcp-check",
    )
    nested_candidates = (
        "option",
        "no",
        "acl",
        "stats",
        "tcp-request",
        "tcp-response",
        "http-request",
        "http-response",
        "http-after-response",
        "mode",
        "balance",
        "bind",
        "server",
    )
    statement_rule_keywords = sorted(
        rule.keyword
        for rule in schema.statement_rules
        if rule.keyword in {"mode", "balance", "bind", "server"}
    )
    rules = {
        "argument_model_skip_keywords": sorted(
            skip_candidates
        ),
        "nested_diagnostic_keywords": sorted(
            nested_candidates
        ),
        "statement_rule_keywords": statement_rule_keywords,
        "server_address_option_policies": {
            "source": "serverSource",
            "usesrc": "serverUsesrc",
            "socks4": "serverSocks4",
        },
        "special_argument_rules": {},
    }
    return rules, {"origin": "derived", "rule": "statement_rules and address policy names"}


def _extract_runtime_metadata(version: str, haproxy_root: Path | None) -> tuple[dict[str, Any], dict[str, Any]]:
    if haproxy_root is None or not haproxy_root.is_dir():
        return {}, {"missing_haproxy_root": str(haproxy_root) if haproxy_root else ""}
    metadata: dict[str, Any] = {"validation_rules": {"special_argument_rules": {}}}
    provenance: dict[str, Any] = {}

    sample_types, sample_types_provenance = extract_sample_types(haproxy_root)
    metadata["sample_types"] = sample_types
    provenance["sample_types"] = sample_types_provenance

    sample_casts, sample_casts_provenance = extract_sample_casts(haproxy_root)
    metadata["sample_casts"] = sample_casts
    provenance["sample_casts"] = sample_casts_provenance

    address_policies, address_provenance = extract_address_policies(haproxy_root)
    metadata["address_policies"] = address_policies
    provenance["address_policies"] = address_provenance

    cookie_modes, cookie_provenance = extract_cookie_modes(haproxy_root)
    metadata["validation_rules"]["special_argument_rules"]["cookie"] = {"modes": cookie_modes}
    provenance["validation_rules.special_argument_rules.cookie"] = cookie_provenance

    mysql_rule, mysql_provenance = extract_mysql_check_rule(haproxy_root)
    metadata["validation_rules"]["special_argument_rules"]["option mysql-check"] = mysql_rule
    provenance["validation_rules.special_argument_rules.option mysql-check"] = mysql_provenance

    header_rule, header_provenance = extract_http_send_name_header_rule(haproxy_root, version)
    metadata["validation_rules"]["special_argument_rules"]["http-send-name-header"] = header_rule
    provenance["validation_rules.special_argument_rules.http-send-name-header"] = header_provenance

    fetch_min, converter_min, min_provenance = extract_sample_min_args(haproxy_root)
    metadata["validation_rules"]["fetch_min_args"] = fetch_min
    metadata["validation_rules"]["converter_min_args"] = converter_min
    provenance.update(min_provenance)
    return metadata, provenance


def build_schema_metadata(
    version: str,
    haproxy_root: Path | None,
    schema: HaproxySchema,
) -> MetadataBuild:
    extracted, extracted_provenance = _extract_runtime_metadata(version, haproxy_root)
    symbols, symbols_provenance = _derive_symbols(schema)
    semantic_groups, semantic_provenance = _derive_semantic_groups(schema)
    validation_rules, validation_provenance = _derive_validation_rules(schema)
    derived = {
        "symbols": symbols,
        "semantic_groups": semantic_groups,
        "validation_rules": validation_rules,
    }
    metadata = _deep_merge(extracted, derived)
    provenance = {
        **extracted_provenance,
        "symbols": symbols_provenance,
        "semantic_groups": semantic_provenance,
        "validation_rules": validation_provenance,
    }
    curated_runtime: dict[str, Any] = {}
    for path, category, value, reason, accepted in iter_curated_entries(load_curated_metadata(version)):
        _put_path(metadata, path, value)
        provenance[path] = {
            "origin": "curated" if category != "curated_runtime" else "curated_runtime",
            "category": category,
            "reason": reason,
            "accepted": accepted,
        }
        if category == "curated_runtime":
            curated_runtime[path] = {"reason": reason, "accepted": accepted}
    return MetadataBuild(metadata=metadata, provenance=provenance, curated_runtime=curated_runtime)


def apply_built_schema_metadata(schema: HaproxySchema, build: MetadataBuild) -> None:
    report = build.report(schema.version)
    if not report["ok"]:
        missing = ", ".join(report["missing_required_fields"])
        raise ValueError(f"schema metadata build is missing required fields: {missing}")
    apply_schema_metadata(schema, build.metadata)
    setattr(schema, "_metadata_provenance_report", report)
