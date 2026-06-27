from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FixedSlotSpec:
    role: str
    port: str | None = None
    address_policy: str | None = None


@dataclass
class StatementRule:
    """Describes how to classify tokens on a configuration line for IDE features."""

    keyword: str
    kind: str
    group: str | None = None
    match_tokens: list[str] = field(default_factory=list)
    minimum_token_index: int | None = None
    value_token_index: int | None = None
    action_token_index: int | None = None
    phase_token_index: int | None = None
    nested_start_index: int | None = None
    prefix: str | None = None
    sections: list[str] = field(default_factory=list)
    fixed_slots: list[FixedSlotSpec] = field(default_factory=list)
    reference_kind: str | None = None
    definition_kind: str | None = None
    symbol_name_token_index: int | None = None


@dataclass(frozen=True)
class ReferencePattern:
    match_tokens: list[str]
    reference_kind: str
    target_token_index: int
    scope: str = "global"
    split: str | None = None


# Static rules for nested / composite statements (merged into schema at build time).
BASE_STATEMENT_RULES: list[StatementRule] = [
    StatementRule(
        keyword="option",
        kind="option",
        group="options",
        match_tokens=["option"],
        minimum_token_index=1,
        value_token_index=1,
    ),
    StatementRule(
        keyword="option",
        kind="option",
        group="options",
        match_tokens=["no", "option"],
        minimum_token_index=2,
        value_token_index=2,
        prefix="no",
    ),
    StatementRule(
        keyword="bind",
        kind="bind",
        group="bind_options",
        match_tokens=["bind"],
        minimum_token_index=2,
        nested_start_index=2,
        fixed_slots=[FixedSlotSpec(role="address", port="required", address_policy="bind")],
    ),
    StatementRule(
        keyword="default-server",
        kind="server",
        group="server_options",
        match_tokens=["default-server"],
        minimum_token_index=1,
        nested_start_index=1,
    ),
    StatementRule(
        keyword="server",
        kind="server",
        group="server_options",
        match_tokens=["server"],
        minimum_token_index=3,
        nested_start_index=3,
        fixed_slots=[
            FixedSlotSpec(role="name"),
            FixedSlotSpec(role="address", port="optional", address_policy="server"),
        ],
        definition_kind="server",
        symbol_name_token_index=1,
    ),
    StatementRule(
        keyword="http-request",
        kind="http-request",
        group="http_request_actions",
        match_tokens=["http-request"],
        minimum_token_index=1,
        action_token_index=1,
    ),
    StatementRule(
        keyword="http-response",
        kind="http-response",
        group="http_response_actions",
        match_tokens=["http-response"],
        minimum_token_index=1,
        action_token_index=1,
    ),
    StatementRule(
        keyword="http-after-response",
        kind="http-after-response",
        group="http_after_response_actions",
        match_tokens=["http-after-response"],
        minimum_token_index=1,
        action_token_index=1,
    ),
    StatementRule(
        keyword="tcp-request",
        kind="tcp-request",
        group="tcp_request_actions",
        match_tokens=["tcp-request"],
        minimum_token_index=1,
        phase_token_index=1,
        action_token_index=2,
    ),
    StatementRule(
        keyword="tcp-response",
        kind="tcp-response",
        group="tcp_response_actions",
        match_tokens=["tcp-response"],
        minimum_token_index=1,
        phase_token_index=1,
        action_token_index=2,
    ),
    StatementRule(
        keyword="acl",
        kind="acl-criterion",
        group="acl_criteria",
        match_tokens=["acl"],
        minimum_token_index=2,
        value_token_index=2,
        definition_kind="acl",
        symbol_name_token_index=1,
    ),
    StatementRule(
        keyword="filter",
        kind="filter",
        group="filters",
        match_tokens=["filter"],
        minimum_token_index=1,
        value_token_index=1,
        definition_kind="filter",
        symbol_name_token_index=1,
    ),
    StatementRule(
        keyword="use_backend",
        kind="directive",
        match_tokens=["use_backend"],
        minimum_token_index=1,
        value_token_index=1,
        reference_kind="proxy-section",
    ),
    StatementRule(
        keyword="use-server",
        kind="directive",
        match_tokens=["use-server"],
        minimum_token_index=1,
        value_token_index=1,
        reference_kind="server",
    ),
    StatementRule(
        keyword="default_backend",
        kind="directive",
        match_tokens=["default_backend"],
        minimum_token_index=1,
        value_token_index=1,
        reference_kind="proxy-section",
    ),
    StatementRule(
        keyword="balance",
        kind="directive",
        match_tokens=["balance"],
        minimum_token_index=1,
        value_token_index=1,
    ),
    StatementRule(
        keyword="mode",
        kind="directive",
        match_tokens=["mode"],
        minimum_token_index=1,
        value_token_index=1,
    ),
]


REFERENCE_PATTERNS: list[ReferencePattern] = [
    ReferencePattern(match_tokens=["resolvers"], reference_kind="resolvers", target_token_index=1),
    ReferencePattern(match_tokens=["peers"], reference_kind="peers", target_token_index=1),
    ReferencePattern(match_tokens=["cache-use"], reference_kind="cache", target_token_index=1),
    ReferencePattern(match_tokens=["cache-store"], reference_kind="cache", target_token_index=1),
    ReferencePattern(
        match_tokens=["filter", "cache"],
        reference_kind="cache",
        target_token_index=2,
    ),
    ReferencePattern(
        match_tokens=["filter-sequence"],
        reference_kind="filter",
        target_token_index=2,
        scope="section",
        split=",",
    ),
]


def statement_rules_from_dicts(rules: list[dict]) -> list[StatementRule]:
    out: list[StatementRule] = []
    for rule in rules:
        fixed_slots = [
            FixedSlotSpec(
                role=slot["role"],
                port=slot.get("port"),
                address_policy=slot.get("address_policy"),
            )
            for slot in rule.get("fixed_slots", [])
        ]
        out.append(
            StatementRule(
                keyword=rule["keyword"],
                kind=rule["kind"],
                group=rule.get("group"),
                match_tokens=rule.get("match_tokens", []),
                minimum_token_index=rule.get("minimum_token_index"),
                value_token_index=rule.get("value_token_index"),
                action_token_index=rule.get("action_token_index"),
                phase_token_index=rule.get("phase_token_index"),
                nested_start_index=rule.get("nested_start_index"),
                prefix=rule.get("prefix"),
                sections=rule.get("sections", []),
                fixed_slots=fixed_slots,
                reference_kind=rule.get("reference_kind"),
                definition_kind=rule.get("definition_kind"),
                symbol_name_token_index=rule.get("symbol_name_token_index"),
            )
        )
    return out


def statement_rules_to_dict(rules: list[StatementRule]) -> list[dict]:
    out: list[dict] = []
    for rule in rules:
        item: dict = {"keyword": rule.keyword, "kind": rule.kind}
        if rule.group:
            item["group"] = rule.group
        if rule.match_tokens:
            item["match_tokens"] = rule.match_tokens
        if rule.minimum_token_index is not None:
            item["minimum_token_index"] = rule.minimum_token_index
        if rule.value_token_index is not None:
            item["value_token_index"] = rule.value_token_index
        if rule.action_token_index is not None:
            item["action_token_index"] = rule.action_token_index
        if rule.phase_token_index is not None:
            item["phase_token_index"] = rule.phase_token_index
        if rule.nested_start_index is not None:
            item["nested_start_index"] = rule.nested_start_index
        if rule.prefix:
            item["prefix"] = rule.prefix
        if rule.sections:
            item["sections"] = rule.sections
        if rule.fixed_slots:
            item["fixed_slots"] = [
                {
                    "role": slot.role,
                    "port": slot.port,
                    **({"address_policy": slot.address_policy} if slot.address_policy else {}),
                }
                for slot in rule.fixed_slots
            ]
        if rule.reference_kind:
            item["reference_kind"] = rule.reference_kind
        if rule.definition_kind:
            item["definition_kind"] = rule.definition_kind
        if rule.symbol_name_token_index is not None:
            item["symbol_name_token_index"] = rule.symbol_name_token_index
        out.append(item)
    return out


def reference_patterns_to_dict(patterns: list[ReferencePattern]) -> list[dict]:
    return [
        {
            "match_tokens": pattern.match_tokens,
            "reference_kind": pattern.reference_kind,
            "target_token_index": pattern.target_token_index,
            "scope": pattern.scope,
            **({"split": pattern.split} if pattern.split else {}),
        }
        for pattern in patterns
    ]
