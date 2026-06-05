from __future__ import annotations

from pathlib import Path

from .dkall_parser import DkallParseResult
from .dkall_supplement import supplement_missing_tls_options
from .doc_parser import DocParseResult
from .hapee_extensions import HAPEE_SECTION_KEYWORDS
from .schema import HaproxySchema, Keyword, SampleFunction, Section, StatementRule
from .signature_model import attach_argument_models
from .slot_model import enrich_statement_rules
from .statement_rules import BASE_STATEMENT_RULES, statement_rules_from_dicts, statement_rules_to_dict


def _ensure_keyword(schema: HaproxySchema, keyword: str) -> Keyword:
    if keyword not in schema.keywords:
        schema.keywords[keyword] = Keyword(name=keyword)
    return schema.keywords[keyword]


def _add_keyword_to_section(schema: HaproxySchema, section: str, keyword: str) -> None:
    sec = schema.sections.setdefault(section, Section(name=section, keywords=[]))
    if keyword not in sec.keywords:
        sec.keywords.append(keyword)
    kw = _ensure_keyword(schema, keyword)
    if section not in kw.sections:
        kw.sections.append(section)


def _mark_source(schema: HaproxySchema, keyword: str, source: str) -> None:
    kw = _ensure_keyword(schema, keyword)
    if source not in kw.sources:
        kw.sources.append(source)


# Documented tcp rule actions not enumerated in dkall's action registry.
_TCP_RULE_ACTIONS = {"accept", "reject", "inspect-delay", "expect-proxy"}


def build_action_groups(doc: DocParseResult, dkall: DkallParseResult) -> dict[str, list[str]]:
    """Merge section 4.3 action matrix (doc) with dkall action registries."""
    am = doc.action_matrix

    def doc_actions(key: str) -> set[str]:
        return set(am.get(key, set()))

    return {
        "http_request_actions": sorted(dkall.http_request_actions | doc_actions("http_request_actions")),
        "http_response_actions": sorted(dkall.http_response_actions | doc_actions("http_response_actions")),
        "http_after_response_actions": sorted(
            dkall.http_after_response_actions | doc_actions("http_after_response_actions")
        ),
        "tcp_request_actions": sorted(
            dkall.tcp_request_actions | doc_actions("tcp_request_actions") | _TCP_RULE_ACTIONS
        ),
        "tcp_response_actions": sorted(
            dkall.tcp_response_actions | doc_actions("tcp_response_actions") | {"accept", "reject"}
        ),
        "quic_initial_actions": sorted(doc_actions("quic_initial_actions")),
    }


def _collect_doc_options(doc: DocParseResult) -> set[str]:
    options: set[str] = set()
    for keywords in doc.matrix_keywords.values():
        for keyword in keywords:
            if keyword.startswith("option "):
                options.add(keyword[len("option ") :])
    for keyword in doc.signatures:
        if keyword.startswith("option "):
            options.add(keyword[len("option ") :])
    return options


def merge_schema(
    version: str,
    doc: DocParseResult,
    dkall: DkallParseResult,
    *,
    dkall_package_dir: Path | None = None,
) -> HaproxySchema:
    if dkall_package_dir is not None:
        supplement_missing_tls_options(dkall, dkall_package_dir)

    schema = HaproxySchema(version=version)

    # Doc is authoritative for top-level section applicability.
    for keyword in doc.global_keywords:
        _add_keyword_to_section(schema, "global", keyword)
        _mark_source(schema, keyword, "doc")

    for section, keywords in doc.matrix_keywords.items():
        for keyword in keywords:
            _add_keyword_to_section(schema, section, keyword)
            _mark_source(schema, keyword, "doc")

    for keyword, sigs in doc.signatures.items():
        kw = _ensure_keyword(schema, keyword)
        for sig in sigs:
            if sig not in kw.signatures:
                kw.signatures.append(sig)
        kdoc = doc.keyword_docs.get(keyword)
        if kdoc:
            if kdoc.arguments:
                kw.arguments = list(kdoc.arguments)
            for section in kdoc.sections:
                _add_keyword_to_section(schema, section, keyword)
        _mark_source(schema, keyword, "doc")

    for section, keywords in doc.section_keywords.items():
        for keyword in keywords:
            _add_keyword_to_section(schema, section, keyword)
            _mark_source(schema, keyword, "doc")
            kdoc = doc.keyword_docs.get(keyword)
            if kdoc:
                kw = _ensure_keyword(schema, keyword)
                if section not in kw.sections:
                    kw.sections.append(section)

    # Dkall complements top-level sections not fully covered by doc.
    for section, keywords in dkall.section_keywords.items():
        for keyword in keywords:
            if section in {"defaults", "frontend", "listen", "backend", "global"}:
                if keyword in schema.keywords:
                    _mark_source(schema, keyword, "dkall")
                    continue
            _add_keyword_to_section(schema, section, keyword)
            _mark_source(schema, keyword, "dkall")

    doc_options = _collect_doc_options(doc)
    action_groups = build_action_groups(doc, dkall)
    schema.keyword_groups = {
        "bind_options": sorted(dkall.bind_options),
        "server_options": sorted(dkall.server_options),
        "options": sorted(set(dkall.options) | doc_options),
        "acl_criteria": sorted(dkall.acl_criteria),
        "sample_fetches": sorted(dkall.sample_fetches),
        "sample_converters": sorted(dkall.sample_converters),
        "filters": sorted(dkall.filters),
        "services": sorted(dkall.services),
        **action_groups,
    }

    for section in schema.sections.values():
        section.keywords.sort()
    for keyword in schema.keywords.values():
        keyword.sections.sort()
        keyword.signatures.sort()
        keyword.sources.sort()

    attach_argument_models(schema.keywords)

    enriched_rules = enrich_statement_rules(
        statement_rules_to_dict(list(BASE_STATEMENT_RULES)),
        schema.keywords,
    )
    schema.statement_rules = statement_rules_from_dicts(enriched_rules)
    for section in sorted(dkall.section_keywords.keys()):
        if section not in schema.sections:
            schema.sections[section] = Section(name=section, keywords=sorted(dkall.section_keywords[section]))

    schema.sample_fetches = {
        name: SampleFunction(
            name=info.name,
            args=info.args,
            out_type=info.out_type,
            contexts=info.contexts,
        )
        for name, info in dkall.sample_fetches_structured.items()
    }
    schema.sample_converters = {
        name: SampleFunction(
            name=info.name,
            args=info.args,
            in_type=info.in_type,
            out_type=info.out_type,
        )
        for name, info in dkall.sample_converters_structured.items()
    }

    apply_hapee_extensions(schema)

    schema.tokens["no_prefix_keywords"] = sorted(doc.no_prefix_keywords)
    schema.tokens["named_defaults_keywords"] = sorted(doc.named_defaults_keywords)

    acl = doc.acl_reference
    schema.tokens["acl_flags"] = sorted(acl.flags.keys())
    schema.tokens["acl_match_methods"] = sorted(acl.match_methods.keys())
    schema.tokens["acl_int_operators"] = sorted(acl.int_operators.keys())
    schema.tokens["acl_string_match_methods"] = sorted(acl.string_match_methods.keys())
    schema.tokens["acl_predefined"] = sorted(acl.predefined_acls.keys())

    return schema


def apply_hapee_extensions(schema: HaproxySchema) -> None:
    for section, keywords in HAPEE_SECTION_KEYWORDS.items():
        for keyword in keywords:
            _add_keyword_to_section(schema, section, keyword)
            _mark_source(schema, keyword, "hapee")
