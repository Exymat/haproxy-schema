from __future__ import annotations

from .dkall_parser import DkallParseResult
from .doc_parser import DocParseResult
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


def merge_schema(version: str, doc: DocParseResult, dkall: DkallParseResult) -> HaproxySchema:
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
        if kdoc and kdoc.arguments:
            kw.arguments = list(kdoc.arguments)
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

    doc_options = _collect_doc_options(doc)
    schema.keyword_groups = {
        "bind_options": sorted(dkall.bind_options),
        "server_options": sorted(dkall.server_options),
        "options": sorted(set(dkall.options) | doc_options),
        "http_request_actions": sorted(dkall.http_request_actions),
        "http_response_actions": sorted(dkall.http_response_actions),
        "http_after_response_actions": sorted(dkall.http_after_response_actions),
        "tcp_request_actions": sorted(set(dkall.tcp_request_actions) | _TCP_RULE_ACTIONS),
        "tcp_response_actions": sorted(set(dkall.tcp_response_actions) | _TCP_RULE_ACTIONS),
        "acl_criteria": sorted(dkall.acl_criteria),
        "sample_fetches": sorted(dkall.sample_fetches),
        "sample_converters": sorted(dkall.sample_converters),
        "filters": sorted(dkall.filters),
        "services": sorted(dkall.services),
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

    return schema
