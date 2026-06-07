from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .dkall_parser import DkallParseResult, parse_dkall
from .doc_parser import DocParseResult, parse_configuration
from .merge import build_action_groups, merge_schema
from .options_metadata import collect_options_with_value
from .schema import HaproxySchema, Keyword, StatementRule


@dataclass
class GroupSyncAudit:
    name: str
    schema_count: int = 0
    source_count: int = 0
    missing_from_schema: list[str] = field(default_factory=list)
    extra_in_schema: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "schema_count": self.schema_count,
            "source_count": self.source_count,
            "missing_from_schema": self.missing_from_schema,
            "extra_in_schema": self.extra_in_schema,
        }


@dataclass
class KeywordIssue:
    keyword: str
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"keyword": self.keyword, "issues": self.issues}


@dataclass
class KeywordFidelityAudit:
    keyword: str
    sections: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    signatures: list[str] = field(default_factory=list)
    signature_count: int = 0
    description_present: bool = False
    doc_argument_count: int = 0
    doc_argument_value_count: int = 0
    argument_model_present: bool = False
    argument_model_min_args: int | None = None
    argument_model_max_args: int | None = None
    argument_model_slot_count: int = 0
    argument_model_slots: list[dict[str, Any]] = field(default_factory=list)
    statement_rule_kind: str = ""
    statement_rule_group: str = ""
    nested_start_index: int | None = None
    fixed_slots: list[dict[str, Any]] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "keyword": self.keyword,
            "sections": self.sections,
            "sources": self.sources,
            "signature_count": self.signature_count,
            "description_present": self.description_present,
            "doc_argument_count": self.doc_argument_count,
            "doc_argument_value_count": self.doc_argument_value_count,
            "statement_rule_kind": self.statement_rule_kind,
            "statement_rule_group": self.statement_rule_group,
            "nested_start_index": self.nested_start_index,
            "fixed_slots": self.fixed_slots,
            "signatures": self.signatures,
            "argument_model_present": self.argument_model_present,
            "argument_model_min_args": self.argument_model_min_args,
            "argument_model_max_args": self.argument_model_max_args,
            "argument_model_slot_count": self.argument_model_slot_count,
            "argument_model_slots": self.argument_model_slots,
            "issues": self.issues,
        }


@dataclass
class GroupItemFidelityAudit:
    group: str
    name: str
    signature_count: int = 0
    description_present: bool = False
    contexts: list[str] = field(default_factory=list)
    takes_value_expected: bool = False
    in_schema_value_group: bool = False
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "group": self.group,
            "name": self.name,
            "signature_count": self.signature_count,
            "description_present": self.description_present,
            "contexts": self.contexts,
            "takes_value_expected": self.takes_value_expected,
            "in_schema_value_group": self.in_schema_value_group,
            "issues": self.issues,
        }


@dataclass
class StructuredFunctionAudit:
    total_count: int = 0
    structured_count: int = 0
    missing_structured: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_count": self.total_count,
            "structured_count": self.structured_count,
            "missing_structured": self.missing_structured,
        }


@dataclass
class SchemaFidelityReport:
    version: str
    keywords_with_signatures_count: int = 0
    keywords_with_argument_model_count: int = 0
    keywords_without_argument_model: list[str] = field(default_factory=list)
    keyword_argument_issues: list[KeywordIssue] = field(default_factory=list)
    keywords: list[KeywordFidelityAudit] = field(default_factory=list)
    group_items: list[GroupItemFidelityAudit] = field(default_factory=list)
    group_sync: list[GroupSyncAudit] = field(default_factory=list)
    value_group_sync: list[GroupSyncAudit] = field(default_factory=list)
    bind_option_docs_missing_signatures: list[str] = field(default_factory=list)
    bind_option_docs_missing_description: list[str] = field(default_factory=list)
    server_option_docs_missing_signatures: list[str] = field(default_factory=list)
    server_option_docs_missing_description: list[str] = field(default_factory=list)
    sample_fetches: StructuredFunctionAudit = field(default_factory=StructuredFunctionAudit)
    sample_converters: StructuredFunctionAudit = field(default_factory=StructuredFunctionAudit)
    sample_fetch_docs_count: int = 0
    sample_converter_docs_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "keywords_with_signatures_count": self.keywords_with_signatures_count,
            "keywords_with_argument_model_count": self.keywords_with_argument_model_count,
            "keywords_without_argument_model": self.keywords_without_argument_model,
            "keyword_argument_issues": [item.to_dict() for item in self.keyword_argument_issues],
            "keywords": [item.to_dict() for item in self.keywords],
            "group_items": [item.to_dict() for item in self.group_items],
            "group_sync": [item.to_dict() for item in self.group_sync],
            "value_group_sync": [item.to_dict() for item in self.value_group_sync],
            "bind_option_docs_missing_signatures": self.bind_option_docs_missing_signatures,
            "bind_option_docs_missing_description": self.bind_option_docs_missing_description,
            "server_option_docs_missing_signatures": self.server_option_docs_missing_signatures,
            "server_option_docs_missing_description": self.server_option_docs_missing_description,
            "sample_fetches": self.sample_fetches.to_dict(),
            "sample_converters": self.sample_converters.to_dict(),
            "sample_fetch_docs_count": self.sample_fetch_docs_count,
            "sample_converter_docs_count": self.sample_converter_docs_count,
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


def _group_sync(name: str, schema_items: list[str], source_items: set[str]) -> GroupSyncAudit:
    schema_set = set(schema_items)
    return GroupSyncAudit(
        name=name,
        schema_count=len(schema_set),
        source_count=len(source_items),
        missing_from_schema=sorted(source_items - schema_set),
        extra_in_schema=sorted(schema_set - source_items),
    )


def _value_group_sync(name: str, schema_items: list[str], source_items: set[str]) -> GroupSyncAudit:
    schema_set = set(schema_items)
    return GroupSyncAudit(
        name=name,
        schema_count=len(schema_set),
        source_count=len(source_items),
        missing_from_schema=sorted(source_items - schema_set),
        extra_in_schema=sorted(schema_set - source_items),
    )


def _signature_syntax_leaks(slot: dict[str, Any]) -> bool:
    for value in slot.get("enum", []):
        if any(ch in value for ch in "<>[]"):
            return True
    return False


def _expected_value_kind(role: str) -> str | None:
    if role == "address":
        return "address"
    if role == "name":
        return "name"
    if role == "value":
        return "generic"
    return None


def _inspect_keyword_argument_model(keyword: str, kw: Keyword, rule: StatementRule | None) -> list[str]:
    issues: list[str] = []
    model = kw.argument_model
    if kw.signatures and model is None:
        return ["missing_argument_model"]
    if model is None:
        return issues

    slots = list(model.slots)
    if any(_signature_syntax_leaks(slot) for slot in slots):
        issues.append("enum_contains_signature_syntax")
    if kw.arguments and not slots:
        issues.append("doc_arguments_present_but_model_has_no_slots")

    if rule and rule.fixed_slots:
        if len(slots) < len(rule.fixed_slots):
            issues.append("fewer_argument_slots_than_fixed_slots")
        for idx, fixed in enumerate(rule.fixed_slots):
            if idx >= len(slots):
                break
            slot = slots[idx]
            expected_kind = _expected_value_kind(fixed.role)
            if expected_kind and slot.get("value_kind") != expected_kind:
                issues.append(f"fixed_slot_{idx}_{fixed.role}_kind_mismatch")
            if fixed.role == "address" and slot.get("enum"):
                issues.append(f"fixed_slot_{idx}_{fixed.role}_has_enum_literals")
        if keyword in {"nameserver"} and model.min_args < len(rule.fixed_slots):
            issues.append("min_args_lower_than_fixed_slot_count")
        if rule.nested_start_index is not None and len(rule.fixed_slots) + 1 != rule.nested_start_index:
            issues.append("nested_start_index_mismatch_fixed_slots")

    if kw.arguments:
        value_docs = sum(len(item.values) for item in kw.arguments)
        if value_docs and not any(slot.get("enum") for slot in slots):
            issues.append("doc_argument_values_not_reflected_in_model")

    return sorted(set(issues))


def _keyword_fidelity_audit(
    schema: HaproxySchema,
    doc: DocParseResult,
    keyword: str,
) -> KeywordFidelityAudit | None:
    rule = next((item for item in schema.statement_rules if item.keyword == keyword), None)
    kw = schema.keywords.get(keyword)
    if kw is None:
        return None
    model = kw.argument_model
    doc_item = doc.keyword_docs.get(keyword)
    return KeywordFidelityAudit(
        keyword=keyword,
        sections=list(kw.sections),
        sources=list(kw.sources),
        signature_count=len(kw.signatures),
        description_present=bool(doc_item and doc_item.description.strip()),
        doc_argument_count=len(kw.arguments),
        doc_argument_value_count=sum(len(item.values) for item in kw.arguments),
        statement_rule_kind=rule.kind if rule else "",
        statement_rule_group=rule.group if rule and rule.group else "",
        nested_start_index=rule.nested_start_index if rule else None,
        fixed_slots=[
            {
                "role": slot.role,
                "port": slot.port,
                "address_policy": slot.address_policy,
            }
            for slot in (rule.fixed_slots if rule else [])
        ],
        signatures=list(kw.signatures),
        argument_model_present=model is not None,
        argument_model_min_args=model.min_args if model else None,
        argument_model_max_args=model.max_args if model else None,
        argument_model_slot_count=len(model.slots) if model else 0,
        argument_model_slots=list(model.slots) if model else [],
        issues=_inspect_keyword_argument_model(keyword, kw, rule),
    )


def _option_doc_description_present(item: Any) -> bool:
    return bool(getattr(item, "description", "").strip())


def _group_item_audit(
    *,
    group: str,
    name: str,
    doc_item: Any | None,
    takes_value_expected: bool,
    in_schema_value_group: bool,
) -> GroupItemFidelityAudit:
    signature_count = len(getattr(doc_item, "signatures", []) or []) if doc_item is not None else 0
    contexts = list(getattr(doc_item, "contexts", []) or []) if doc_item is not None else []
    description_present = _option_doc_description_present(doc_item) if doc_item is not None else False
    issues: list[str] = []
    if signature_count == 0:
        issues.append("missing_signature")
    if not description_present:
        issues.append("missing_description")
    if takes_value_expected != in_schema_value_group:
        issues.append("takes_value_mismatch")
    return GroupItemFidelityAudit(
        group=group,
        name=name,
        signature_count=signature_count,
        description_present=description_present,
        contexts=contexts,
        takes_value_expected=takes_value_expected,
        in_schema_value_group=in_schema_value_group,
        issues=issues,
    )


def _structured_function_audit(raw_names: set[str], structured: dict[str, Any]) -> StructuredFunctionAudit:
    return StructuredFunctionAudit(
        total_count=len(raw_names),
        structured_count=len(structured),
        missing_structured=sorted(raw_names - set(structured.keys())),
    )


def build_schema_fidelity_report(version: str, doc_path: Path, dkall_path: Path) -> SchemaFidelityReport:
    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    schema = merge_schema(version, doc, dkall, dkall_package_dir=dkall_path.parent)

    rules_by_keyword = {rule.keyword: rule for rule in schema.statement_rules}
    keyword_names_with_signatures = sorted(name for name, kw in schema.keywords.items() if kw.signatures)
    keywords_without_argument_model = sorted(
        name for name in keyword_names_with_signatures if schema.keywords[name].argument_model is None
    )

    keyword_argument_issues: list[KeywordIssue] = []
    for keyword in keyword_names_with_signatures:
        kw = schema.keywords[keyword]
        issues = _inspect_keyword_argument_model(keyword, kw, rules_by_keyword.get(keyword))
        if issues and issues != ["missing_argument_model"]:
            keyword_argument_issues.append(KeywordIssue(keyword=keyword, issues=issues))

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

    group_sync = [
        _group_sync("bind_options", schema.keyword_groups.get("bind_options", []), set(dkall.bind_options)),
        _group_sync("server_options", schema.keyword_groups.get("server_options", []), set(dkall.server_options)),
        _group_sync("options", schema.keyword_groups.get("options", []), set(dkall.options) | doc_options),
        _group_sync(
            "http_request_actions",
            schema.keyword_groups.get("http_request_actions", []),
            set(action_groups["http_request_actions"]),
        ),
        _group_sync(
            "http_response_actions",
            schema.keyword_groups.get("http_response_actions", []),
            set(action_groups["http_response_actions"]),
        ),
        _group_sync(
            "http_after_response_actions",
            schema.keyword_groups.get("http_after_response_actions", []),
            set(action_groups["http_after_response_actions"]),
        ),
        _group_sync(
            "tcp_request_actions",
            schema.keyword_groups.get("tcp_request_actions", []),
            set(action_groups["tcp_request_actions"]),
        ),
        _group_sync(
            "tcp_response_actions",
            schema.keyword_groups.get("tcp_response_actions", []),
            set(action_groups["tcp_response_actions"]),
        ),
        _group_sync(
            "quic_initial_actions",
            schema.keyword_groups.get("quic_initial_actions", []),
            set(action_groups["quic_initial_actions"]),
        ),
        _group_sync("acl_criteria", schema.keyword_groups.get("acl_criteria", []), set(dkall.acl_criteria)),
        _group_sync("sample_fetches", schema.keyword_groups.get("sample_fetches", []), set(dkall.sample_fetches)),
        _group_sync(
            "sample_converters",
            schema.keyword_groups.get("sample_converters", []),
            set(dkall.sample_converters),
        ),
        _group_sync("filters", schema.keyword_groups.get("filters", []), set(dkall.filters)),
        _group_sync("services", schema.keyword_groups.get("services", []), set(dkall.services)),
    ]

    value_group_sync = [
        _value_group_sync(
            "options_with_value",
            schema.keyword_groups.get("options_with_value", []),
            set(collect_options_with_value(sorted(set(dkall.options) | doc_options), option_signature_map)),
        ),
        _value_group_sync(
            "bind_options_with_value",
            schema.keyword_groups.get("bind_options_with_value", []),
            set(collect_options_with_value(sorted(dkall.bind_options), bind_signature_map)),
        ),
        _value_group_sync(
            "server_options_with_value",
            schema.keyword_groups.get("server_options_with_value", []),
            set(collect_options_with_value(sorted(dkall.server_options), server_signature_map)),
        ),
    ]

    keywords = [
        audit
        for audit in (
            _keyword_fidelity_audit(schema, doc, keyword)
            for keyword in sorted(schema.keywords.keys())
        )
        if audit is not None
    ]

    bind_expected_with_value = set(collect_options_with_value(sorted(dkall.bind_options), bind_signature_map))
    server_expected_with_value = set(collect_options_with_value(sorted(dkall.server_options), server_signature_map))
    option_expected_with_value = set(
        collect_options_with_value(sorted(set(dkall.options) | doc_options), option_signature_map)
    )
    bind_value_group = set(schema.keyword_groups.get("bind_options_with_value", []))
    server_value_group = set(schema.keyword_groups.get("server_options_with_value", []))
    option_value_group = set(schema.keyword_groups.get("options_with_value", []))

    group_items: list[GroupItemFidelityAudit] = []
    for name in sorted(set(dkall.bind_options) | set(doc.bind_option_docs.keys())):
        group_items.append(
            _group_item_audit(
                group="bind_options",
                name=name,
                doc_item=doc.bind_option_docs.get(name),
                takes_value_expected=name in bind_expected_with_value,
                in_schema_value_group=name in bind_value_group,
            )
        )
    for name in sorted(set(dkall.server_options) | set(doc.server_option_docs.keys())):
        group_items.append(
            _group_item_audit(
                group="server_options",
                name=name,
                doc_item=doc.server_option_docs.get(name),
                takes_value_expected=name in server_expected_with_value,
                in_schema_value_group=name in server_value_group,
            )
        )
    option_doc_lookup = {
        name[len("option ") :]: item
        for name, item in doc.keyword_docs.items()
        if name.startswith("option ")
    }
    for name in sorted((set(dkall.options) | doc_options)):
        group_items.append(
            _group_item_audit(
                group="options",
                name=name,
                doc_item=option_doc_lookup.get(name),
                takes_value_expected=name in option_expected_with_value,
                in_schema_value_group=name in option_value_group,
            )
        )
    for name in sorted(set(dkall.sample_fetches) | set(doc.sample_reference.fetches.keys())):
        doc_item = doc.sample_reference.fetches.get(name)
        group_items.append(
            GroupItemFidelityAudit(
                group="sample_fetches",
                name=name,
                signature_count=1 if doc_item and doc_item.signature else 0,
                description_present=bool(doc_item and doc_item.description),
                issues=[
                    *([] if doc_item and doc_item.signature else ["missing_signature"]),
                    *([] if doc_item and doc_item.description else ["missing_description"]),
                ],
            )
        )
    for name in sorted(set(dkall.sample_converters) | set(doc.sample_reference.converters.keys())):
        doc_item = doc.sample_reference.converters.get(name)
        group_items.append(
            GroupItemFidelityAudit(
                group="sample_converters",
                name=name,
                signature_count=1 if doc_item and doc_item.signature else 0,
                description_present=bool(doc_item and doc_item.description),
                issues=[
                    *([] if doc_item and doc_item.signature else ["missing_signature"]),
                    *([] if doc_item and doc_item.description else ["missing_description"]),
                ],
            )
        )

    return SchemaFidelityReport(
        version=version,
        keywords_with_signatures_count=len(keyword_names_with_signatures),
        keywords_with_argument_model_count=sum(
            1 for name in keyword_names_with_signatures if schema.keywords[name].argument_model is not None
        ),
        keywords_without_argument_model=keywords_without_argument_model,
        keyword_argument_issues=keyword_argument_issues,
        keywords=keywords,
        group_items=group_items,
        group_sync=group_sync,
        value_group_sync=value_group_sync,
        bind_option_docs_missing_signatures=sorted(
            name for name, item in doc.bind_option_docs.items() if not item.signatures
        ),
        bind_option_docs_missing_description=sorted(
            name for name, item in doc.bind_option_docs.items() if not item.description
        ),
        server_option_docs_missing_signatures=sorted(
            name for name, item in doc.server_option_docs.items() if not item.signatures
        ),
        server_option_docs_missing_description=sorted(
            name for name, item in doc.server_option_docs.items() if not item.description
        ),
        sample_fetches=_structured_function_audit(set(dkall.sample_fetches), dkall.sample_fetches_structured),
        sample_converters=_structured_function_audit(
            set(dkall.sample_converters), dkall.sample_converters_structured
        ),
        sample_fetch_docs_count=len(doc.sample_reference.fetches),
        sample_converter_docs_count=len(doc.sample_reference.converters),
    )
