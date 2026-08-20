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
    extract_log_address_skip,
    extract_mysql_check_rule,
    extract_sample_casts,
    extract_sample_fetch_references,
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
    named_section_order = (
        "frontend",
        "backend",
        "listen",
        "defaults",
        "peers",
        "userlist",
        "mailers",
        "http-errors",
        "ring",
        "fcgi-app",
        "healthcheck",
        "acme",
        "log-profile",
        "log-forward",
        "crt-store",
        "traces",
        "program",
    )
    section_kind_order = (
        ("frontend", "proxy-section"),
        ("backend", "proxy-section"),
        ("listen", "proxy-section"),
        ("defaults", "defaults-profile"),
        ("cache", "cache"),
        ("userlist", "userlist"),
        ("resolvers", "resolvers"),
        ("peers", "peers"),
        ("mailers", "mailers"),
        ("http-errors", "http-errors"),
        ("ring", "ring"),
        ("fcgi-app", "fcgi-app"),
        ("healthcheck", "healthcheck"),
        ("acme", "acme"),
        ("log-profile", "log-profile"),
        ("log-forward", "log-forward"),
        ("crt-store", "crt-store"),
        ("traces", "traces"),
        ("program", "program"),
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
        "runtime_mode_context_values": ["http", "tcp"],
        "section_definition_kinds": section_definition_kinds,
        "scoped_symbol_kinds": sorted(definition_kinds),
        "defaults_section_name": "defaults",
        "entry_point_labels": {"listen": "Listen", "frontend": "Frontend"},
        "conventional_defaults_profile_names": ["default"],
        "unused_symbol_section_block_kinds": [
            "proxy-section",
            "defaults-profile",
            "cache",
            "userlist",
            "resolvers",
            "peers",
            "mailers",
            "http-errors",
            "ring",
            "fcgi-app",
            "healthcheck",
            "acme",
            "log-profile",
            "log-forward",
            "crt-store",
            "traces",
            "program",
        ],
        "unused_symbol_skipped_kinds": [
            "filter",
            "server",
            "server-template",
            "peer",
            "mailer",
            "nameserver",
            "acme",
            "crt-store",
            "log-forward",
            "log-profile",
            "program",
            "traces",
        ],
        "duplicate_section_kinds": [
            "proxy-section",
            "defaults-profile",
            "cache",
            "userlist",
            "resolvers",
            "peers",
            "mailers",
            "http-errors",
            "ring",
            "fcgi-app",
            "healthcheck",
            "acme",
            "log-profile",
            "log-forward",
            "crt-store",
            "traces",
            "program",
        ],
        "symbol_kind_labels": {
            "proxy-section": "Proxy section",
            "defaults-profile": "Defaults profile",
            "userlist": "Userlist",
            "cache": "cache section",
            "resolvers": "resolvers section",
            "peers": "peers section",
            "mailers": "mailers section",
            "http-errors": "http-errors section",
            "ring": "ring section",
            "fcgi-app": "fcgi-app section",
            "healthcheck": "healthcheck section",
            "acme": "acme section",
            "log-profile": "log-profile section",
            "log-forward": "log-forward section",
            "crt-store": "crt-store section",
            "traces": "traces section",
            "program": "program section",
            "server-template": "server template",
            "peer": "peer",
            "mailer": "mailer",
            "nameserver": "nameserver",
            "stick-table": "stick-table",
        },
    }
    return symbols, {"origin": "derived", "rule": "sections, statement_rules, and mode docs"}


def _derive_semantic_groups(schema: HaproxySchema) -> tuple[dict[str, Any], dict[str, Any]]:
    action_groups = sorted(name for name in schema.keyword_groups if name.endswith("_actions"))
    completion_map: dict[str, str] = {}
    for group in action_groups:
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
        "acl_ref_groups": [
            group
            for group in (
                "acl_flags",
                "acl_match_methods",
                "acl_int_operators",
                "acl_string_match_methods",
                "acl_predefined",
            )
            if group in schema.keyword_groups
        ],
        "use_service": {
            "rule_kinds": sorted(use_service_rule_kinds),
            "action": "use-service",
            "service_group": "services",
            "allow_prefixes": [],
        },
    }
    return groups, {"origin": "derived", "rule": "keyword_groups and line_option_semantics"}


def _derive_balance_variant_algorithms(schema: HaproxySchema) -> dict[str, str]:
    """Map balance algorithm tokens to sibling keywords with dedicated argument models."""
    balance_kw = schema.keywords.get("balance")
    if balance_kw is None or balance_kw.argument_model is None:
        return {}
    slots = balance_kw.argument_model.slots
    if not slots:
        return {}
    algorithms = {value.lower() for value in slots[0].get("enum", []) if value}
    if not algorithms:
        return {}
    prefix = "balance "
    variant_algorithms: dict[str, str] = {}
    for name, keyword in sorted(schema.keywords.items()):
        if not name.startswith(prefix):
            continue
        algorithm = name[len(prefix) :]
        if algorithm not in algorithms or keyword.argument_model is None:
            continue
        variant_algorithms[algorithm] = name
    return variant_algorithms


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
        "quic-initial",
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
        "quic-initial",
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
        "entry_point_no_bind_message": (
            "{label} '{name}' has no bind directive and cannot accept connections"
        ),
        "address_directives": {
            "log": "log",
            "source": "source",
            "tcp-check": "tcpCheckAddr",
            "http-check": "tcpCheckAddr",
        },
        "nested_keyword_skip_patterns": [
            {"match_tokens": ["tcp-request", "inspect-delay"]},
            {"match_tokens": ["tcp-response", "inspect-delay"]},
        ],
        "unused_symbol_messages": {
            "acl": "ACL '{name}' is defined but never referenced in this section",
            "proxy-section": (
                "Backend '{name}' is never referenced by use_backend or default_backend"
            ),
            "defaults-profile": "Defaults profile '{name}' is never referenced by 'from'",
            "cache": "Cache '{name}' is never referenced",
            "userlist": "Userlist '{name}' is never referenced",
            "resolvers": "Resolvers '{name}' is never referenced",
            "peers": "Peers section '{name}' is never referenced",
            "mailers": "Mailers section '{name}' is never referenced",
            "http-errors": "HTTP errors section '{name}' is never referenced",
            "ring": "Ring section '{name}' is never referenced",
            "fcgi-app": "FCGI app section '{name}' is never referenced",
            "healthcheck": "Healthcheck section '{name}' is never referenced",
            "acme": "ACME section '{name}' is never referenced",
            "log-profile": "Log profile section '{name}' is never referenced",
            "log-forward": "Log-forward section '{name}' is never referenced",
            "crt-store": "CRT store section '{name}' is never referenced",
            "traces": "Traces section '{name}' is never referenced",
            "program": "Program section '{name}' is never referenced",
            "default": "'{name}' appears unused",
        },
        "unused_symbol_codes": {
            "acl": "unused-acl",
            "proxy-section": "unused-section",
            "defaults-profile": "unused-defaults-profile",
            "default": "unused-symbol",
        },
    }
    provenance: dict[str, Any] = {
        "origin": "derived",
        "rule": "statement_rules and address policy names",
    }
    balance_variants = _derive_balance_variant_algorithms(schema)
    if balance_variants:
        rules["special_argument_rules"]["balance"] = {"variant_algorithms": balance_variants}
        provenance["validation_rules.special_argument_rules.balance"] = {
            "origin": "derived",
            "rule": "balance sibling keywords with dedicated argument models",
        }
    return rules, provenance


def _extract_runtime_metadata(version: str, haproxy_root: Path | None) -> tuple[dict[str, Any], dict[str, Any]]:
    if haproxy_root is None or not haproxy_root.is_dir():
        return {}, {"missing_haproxy_root": str(haproxy_root) if haproxy_root else ""}
    validation_rules: dict[str, Any] = {"special_argument_rules": {}}
    metadata: dict[str, Any] = {"validation_rules": validation_rules}
    provenance: dict[str, Any] = {}

    sample_types, sample_types_provenance = extract_sample_types(haproxy_root)
    metadata["sample_types"] = sample_types
    provenance["sample_types"] = sample_types_provenance

    sample_casts, sample_casts_provenance = extract_sample_casts(haproxy_root)
    metadata["sample_casts"] = sample_casts
    provenance["sample_casts"] = sample_casts_provenance

    sample_fetch_references, sample_fetch_references_provenance = extract_sample_fetch_references(haproxy_root)
    metadata["symbols"] = {"sample_fetch_references": sample_fetch_references}
    provenance["symbols.sample_fetch_references"] = sample_fetch_references_provenance

    address_policies, address_provenance = extract_address_policies(haproxy_root)
    metadata["address_policies"] = address_policies
    provenance["address_policies"] = address_provenance

    log_address_skip, log_address_skip_provenance = extract_log_address_skip(haproxy_root)
    validation_rules["log_address_skip"] = log_address_skip
    provenance["validation_rules.log_address_skip"] = log_address_skip_provenance

    cookie_modes, cookie_provenance = extract_cookie_modes(haproxy_root)
    validation_rules["special_argument_rules"]["cookie"] = {"modes": cookie_modes}
    provenance["validation_rules.special_argument_rules.cookie"] = cookie_provenance

    mysql_rule, mysql_provenance = extract_mysql_check_rule(haproxy_root)
    validation_rules["special_argument_rules"]["option mysql-check"] = mysql_rule
    provenance["validation_rules.special_argument_rules.option mysql-check"] = mysql_provenance

    header_rule, header_provenance = extract_http_send_name_header_rule(haproxy_root, version)
    validation_rules["special_argument_rules"]["http-send-name-header"] = header_rule
    provenance["validation_rules.special_argument_rules.http-send-name-header"] = header_provenance

    fetch_min, converter_min, min_provenance = extract_sample_min_args(haproxy_root)
    validation_rules["fetch_min_args"] = fetch_min
    validation_rules["converter_min_args"] = converter_min
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
