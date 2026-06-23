from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from .dkall_parser import DkallParseResult
from .dkall_supplement import supplement_missing_tls_options
from .doc_parser import DocParseResult
from .hapee_extensions import HAPEE_SECTION_KEYWORDS
from .schema import (
    ArgumentParamDoc,
    ArgumentValueDoc,
    FixedSlotSpec,
    HaproxySchema,
    Keyword,
    KeywordVariant,
    LogformatAlias,
    SampleFunction,
    Section,
    StatementRule,
)
from .line_layout import build_line_layout
from .logformat_slots import collect_logformat_slots
from .options_metadata import collect_options_with_value
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
_COMPILE_TIME_DOC_KEYWORD_PREFIXES = ("wurfl-",)


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


def _signatures_by_option(docs: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, item in docs.items():
        out[name.lower()] = list(item.signatures)
    return out


def _argument_docs_from_variant(arguments: list[Any]) -> list[ArgumentParamDoc]:
    return [
        ArgumentParamDoc(
            parameter=argument.parameter,
            description=argument.description,
            values=[
                ArgumentValueDoc(name=value.name, description=value.description) for value in argument.values
            ],
        )
        for argument in arguments
    ]


def _apply_keyword_doc_to_schema(kw: Keyword, kdoc: Any) -> None:
    kw.variants = [
        KeywordVariant(
            chapter=variant.chapter,
            sections=list(variant.sections),
            contexts=list(variant.contexts),
            signatures=list(variant.signatures),
            arguments=_argument_docs_from_variant(variant.arguments),
        )
        for variant in kdoc.variants
    ]
    kw.contexts = list(kdoc.contexts)
    kw.arguments = _argument_docs_from_variant(kdoc.arguments)


def _merge_keyword_variant_docs(
    kw: Keyword,
    kdoc: Any,
    *,
    sections: list[str] | None = None,
    merge_keyword_sections: bool,
    merge_keyword_contexts: bool,
    replace_existing: bool,
) -> None:
    variants = list(kw.variants)
    for source_variant in kdoc.variants:
        target_sections = list(source_variant.sections or sections or [])
        target = next(
            (
                variant
                for variant in variants
                if variant.chapter == source_variant.chapter and variant.sections == target_sections
            ),
            None,
        )
        if target is None:
            target = KeywordVariant(chapter=source_variant.chapter, sections=target_sections)
            variants.append(target)
        for signature in source_variant.signatures:
            if signature not in target.signatures:
                target.signatures.append(signature)
        for context in source_variant.contexts:
            if context not in target.contexts:
                target.contexts.append(context)
        if replace_existing or not target.arguments:
            target.arguments = _argument_docs_from_variant(source_variant.arguments)
    kw.variants = variants
    if merge_keyword_sections:
        for section in sections or kdoc.sections:
            if section not in kw.sections:
                kw.sections.append(section)
    if merge_keyword_contexts:
        for context in kdoc.contexts:
            if context not in kw.contexts:
                kw.contexts.append(context)


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
            _apply_keyword_doc_to_schema(kw, kdoc)
            for section in kdoc.sections:
                _add_keyword_to_section(schema, section, keyword)
        _mark_source(schema, keyword, "doc")

    for option_name, kdoc in doc.bind_option_docs.items():
        kw = _ensure_keyword(schema, option_name)
        _merge_keyword_variant_docs(
            kw,
            kdoc,
            sections=[],
            merge_keyword_sections=False,
            merge_keyword_contexts=False,
            replace_existing=False,
        )
        _mark_source(schema, option_name, "doc")

    for option_name, kdoc in doc.server_option_docs.items():
        kw = _ensure_keyword(schema, option_name)
        _merge_keyword_variant_docs(
            kw,
            kdoc,
            sections=[],
            merge_keyword_sections=False,
            merge_keyword_contexts=False,
            replace_existing=False,
        )
        _mark_source(schema, option_name, "doc")

    for section, keywords in doc.section_keywords.items():
        for keyword in keywords:
            _add_keyword_to_section(schema, section, keyword)
            _mark_source(schema, keyword, "doc")

    # Dkall complements top-level sections not fully covered by doc.
    for section, keywords in dkall.section_keywords.items():
        for keyword in keywords:
            if section in {"defaults", "frontend", "listen", "backend", "global"}:
                if keyword in schema.keywords:
                    _mark_source(schema, keyword, "dkall")
                    continue
            _add_keyword_to_section(schema, section, keyword)
            _mark_source(schema, keyword, "dkall")

    _prune_compile_time_doc_keywords(schema, dkall)

    doc_options = _collect_doc_options(doc)
    action_groups = build_action_groups(doc, dkall)
    option_signature_map = {
        name[len("option ") :].lower(): [
            sig[len("option ") :] if sig.lower().startswith("option ") else sig for sig in kdoc.signatures
        ]
        for name, kdoc in doc.keyword_docs.items()
        if name.startswith("option ")
    }
    bind_signature_map = _signatures_by_option(doc.bind_option_docs)
    server_signature_map = _signatures_by_option(doc.server_option_docs)

    schema.keyword_groups = {
        "bind_options": sorted(dkall.bind_options),
        "bind_options_with_value": sorted(
            collect_options_with_value(sorted(dkall.bind_options), bind_signature_map)
        ),
        "server_options": sorted(dkall.server_options),
        "server_options_with_value": sorted(
            collect_options_with_value(sorted(dkall.server_options), server_signature_map)
        ),
        "options": sorted(set(dkall.options) | doc_options),
        "options_with_value": sorted(
            collect_options_with_value(sorted(set(dkall.options) | doc_options), option_signature_map)
        ),
        "acl_criteria": sorted(dkall.acl_criteria),
        "sample_fetches": sorted(dkall.sample_fetches),
        "sample_converters": sorted(dkall.sample_converters),
        "filters": sorted(dkall.filters),
        "services": sorted(dkall.services),
        **action_groups,
    }
    schema.keyword_group_contexts = {
        "options": {
            name[len("option ") :]: list(kdoc.contexts)
            for name, kdoc in doc.keyword_docs.items()
            if name.startswith("option ") and kdoc.contexts
        },
        "bind_options": {
            name: list(kdoc.contexts) for name, kdoc in doc.bind_option_docs.items() if kdoc.contexts
        },
        "server_options": {
            name: list(kdoc.contexts) for name, kdoc in doc.server_option_docs.items() if kdoc.contexts
        },
    }

    for section in schema.sections.values():
        section.keywords.sort()
    for keyword in schema.keywords.values():
        keyword.sections.sort()
        keyword.contexts.sort()
        keyword.signatures.sort()
        keyword.sources.sort()
        keyword.variants.sort(key=lambda variant: variant.chapter)
        for variant in keyword.variants:
            variant.sections.sort()
            variant.contexts.sort()
            variant.signatures.sort()

    attach_argument_models(cast(dict[str, Any], schema.keywords))

    enriched_rules = enrich_statement_rules(
        statement_rules_to_dict(list(BASE_STATEMENT_RULES)),
        schema.keywords,
    )
    schema.statement_rules = [
        StatementRule(
            keyword=rule.keyword,
            kind=rule.kind,
            group=rule.group,
            value_token_index=rule.value_token_index,
            action_token_index=rule.action_token_index,
            phase_token_index=rule.phase_token_index,
            nested_start_index=rule.nested_start_index,
            prefix=rule.prefix,
            sections=list(rule.sections),
            fixed_slots=[
                FixedSlotSpec(
                    role=slot.role,
                    port=slot.port,
                    address_policy=slot.address_policy,
                )
                for slot in rule.fixed_slots
            ],
            reference_kind=rule.reference_kind,
            definition_kind=rule.definition_kind,
            symbol_name_token_index=rule.symbol_name_token_index,
        )
        for rule in statement_rules_from_dicts(enriched_rules)
    ]
    for section in sorted(dkall.section_keywords.keys()):
        if section not in schema.sections:
            schema.sections[section] = Section(name=section, keywords=sorted(dkall.section_keywords[section]))

    schema.sample_fetches = {
        name: SampleFunction(
            name=info.name,
            args=info.args,
            out_type=info.out_type,
            contexts=info.contexts,
            max_args=len(info.args) if info.args else 0,
            signature=doc.sample_reference.fetches.get(name).signature if name in doc.sample_reference.fetches else "",
            description=doc.sample_reference.fetches.get(name).description if name in doc.sample_reference.fetches else "",
            chapter=doc.sample_reference.fetches.get(name).chapter if name in doc.sample_reference.fetches else "",
            deprecated=doc.sample_reference.fetches.get(name).deprecated if name in doc.sample_reference.fetches else False,
        )
        for name, info in dkall.sample_fetches_structured.items()
    }
    schema.sample_converters = {
        name: SampleFunction(
            name=info.name,
            args=info.args,
            in_type=info.in_type,
            out_type=info.out_type,
            max_args=len(info.args) if info.args else None,
            signature=doc.sample_reference.converters.get(name).signature if name in doc.sample_reference.converters else "",
            description=doc.sample_reference.converters.get(name).description if name in doc.sample_reference.converters else "",
            chapter=doc.sample_reference.converters.get(name).chapter if name in doc.sample_reference.converters else "",
            deprecated=doc.sample_reference.converters.get(name).deprecated if name in doc.sample_reference.converters else False,
        )
        for name, info in dkall.sample_converters_structured.items()
    }

    schema.logformat_aliases = {
        name: LogformatAlias(
            name=item.name,
            field_name=item.field_name,
            sample_fetch=item.sample_fetch,
            type=item.type,
            restrictions=item.restrictions,
            category=item.category,
        )
        for name, item in doc.logformat_reference.aliases.items()
    }
    schema.logformat_slots = collect_logformat_slots(schema.keywords)

    schema.line_layout = build_line_layout(schema.keywords.keys())

    apply_hapee_extensions(schema)

    schema.tokens["no_prefix_keywords"] = sorted(doc.no_prefix_keywords)
    schema.tokens["named_defaults_keywords"] = sorted(doc.named_defaults_keywords)

    acl = doc.acl_reference
    schema.tokens["acl_flags"] = sorted(acl.flags.keys())
    schema.tokens["acl_match_methods"] = sorted(acl.match_methods.keys())
    schema.tokens["acl_int_operators"] = sorted(acl.int_operators.keys())
    schema.tokens["acl_string_match_methods"] = sorted(acl.string_match_methods.keys())
    schema.tokens["acl_predefined"] = sorted(acl.predefined_acls.keys())
    schema.tokens["logformat_flags"] = sorted(doc.logformat_reference.flags.keys())

    return schema


def _prune_compile_time_doc_keywords(schema: HaproxySchema, dkall: DkallParseResult) -> None:
    dkall_keywords = {keyword for keywords in dkall.section_keywords.values() for keyword in keywords}
    to_remove = [
        keyword
        for keyword in schema.keywords
        if keyword.startswith(_COMPILE_TIME_DOC_KEYWORD_PREFIXES) and keyword not in dkall_keywords
    ]
    if not to_remove:
        return
    for keyword in to_remove:
        schema.keywords.pop(keyword, None)
    for section in schema.sections.values():
        section.keywords = [keyword for keyword in section.keywords if keyword not in to_remove]


def apply_hapee_extensions(schema: HaproxySchema) -> None:
    for section, keywords in HAPEE_SECTION_KEYWORDS.items():
        for keyword in keywords:
            _add_keyword_to_section(schema, section, keyword)
            _mark_source(schema, keyword, "hapee")
