"""Authoritative metadata shapes shared with the editor's generated TypeScript contract."""
from typing import Literal, NotRequired, TypedDict


class FetchReference(TypedDict):
    reference_kind: str
    argument_index: NotRequired[int]
    scope: NotRequired[str]


class SelfReference(TypedDict):
    reference_kind: str
    token_index: NotRequired[int]
    scope: NotRequired[str]


class UseService(TypedDict):
    action: str
    allow_prefixes: list[str]
    rule_kinds: list[str]
    service_group: str


class SkipPattern(TypedDict):
    match_tokens: list[str]


class SpecialArgumentRule(TypedDict, total=False):
    modes: list[str]
    values: list[str]
    variant_algorithms: dict[str, str]
    forbidden_first_arg_by_min_version: dict[str, list[str]]


class SchemaSymbols(TypedDict, total=False):
    acl_condition_operators: list[str]
    bind_detect_keywords: list[str]
    conventional_defaults_profile_names: list[str]
    defaults_section_name: str
    duplicate_section_kinds: list[str]
    entry_point_labels: dict[str, str]
    entry_point_sections: list[str]
    named_sections: list[str]
    proxy_sections: list[str]
    runtime_mode_context_values: list[str]
    runtime_modes: list[str]
    sample_fetch_references: dict[str, FetchReference]
    scoped_symbol_kinds: list[str]
    section_definition_kinds: dict[str, str]
    self_reference_keywords: dict[str, SelfReference]
    symbol_kind_labels: dict[str, str]
    unused_symbol_section_block_kinds: list[str]
    unused_symbol_skipped_kinds: list[str]


class SchemaSemanticGroups(TypedDict, total=False):
    acl_criterion_groups: list[str]
    acl_ref_groups: list[str]
    action_groups: list[str]
    common_language_groups: dict[str, str]
    completion_kind_to_action_group: dict[str, str]
    deprecated_action_groups: list[str]
    dynamic_action_prefixes: list[str]
    line_option_group_for_kind: dict[str, str]
    log_format_groups: dict[str, str]
    sample_expression_group_for_kind: dict[str, str]
    use_service: UseService


class SchemaValidationRules(TypedDict, total=False):
    address_directives: dict[str, str]
    argument_model_skip_keywords: list[str]
    converter_min_args: dict[str, int]
    entry_point_no_bind_message: str
    fetch_min_args: dict[str, int]
    log_address_skip: list[str]
    logformat_stop_tokens: list[str]
    nested_diagnostic_keywords: list[str]
    nested_keyword_skip_patterns: list[SkipPattern]
    server_address_option_policies: dict[str, str]
    special_argument_rules: dict[str, SpecialArgumentRule]
    statement_rule_keywords: list[str]
    unused_symbol_codes: dict[str, str]
    unused_symbol_messages: dict[str, str]


ArgumentValueKind = Literal["generic", "enum", "name", "address", "path"]

ArgumentSlot = TypedDict(
    "ArgumentSlot",
    {
        "optional": bool,
        "variadic": bool,
        "enum": list[str],
        "value_kind": ArgumentValueKind,
    },
    total=False,
)
