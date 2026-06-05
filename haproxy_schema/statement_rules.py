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


# Static rules for nested / composite statements (merged into schema at build time).
BASE_STATEMENT_RULES: list[StatementRule] = [
    StatementRule(keyword="option", kind="option", group="options", value_token_index=1),
    StatementRule(
        keyword="option",
        kind="option",
        group="options",
        value_token_index=2,
        prefix="no",
    ),
    StatementRule(
        keyword="bind",
        kind="bind",
        group="bind_options",
        nested_start_index=2,
        fixed_slots=[FixedSlotSpec(role="address", port="required", address_policy="bind")],
    ),
    StatementRule(
        keyword="default-server",
        kind="server",
        group="server_options",
        nested_start_index=1,
    ),
    StatementRule(
        keyword="server",
        kind="server",
        group="server_options",
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
        action_token_index=1,
    ),
    StatementRule(
        keyword="http-response",
        kind="http-response",
        group="http_response_actions",
        action_token_index=1,
    ),
    StatementRule(
        keyword="http-after-response",
        kind="http-after-response",
        group="http_after_response_actions",
        action_token_index=1,
    ),
    StatementRule(
        keyword="tcp-request",
        kind="tcp-request",
        group="tcp_request_actions",
        phase_token_index=1,
        action_token_index=2,
    ),
    StatementRule(
        keyword="tcp-response",
        kind="tcp-response",
        group="tcp_response_actions",
        phase_token_index=1,
        action_token_index=2,
    ),
    StatementRule(
        keyword="acl",
        kind="acl-criterion",
        group="acl_criteria",
        value_token_index=2,
        definition_kind="acl",
        symbol_name_token_index=1,
    ),
    StatementRule(
        keyword="filter",
        kind="filter",
        group="filters",
        value_token_index=1,
        definition_kind="filter",
        symbol_name_token_index=1,
    ),
    StatementRule(
        keyword="use_backend",
        kind="directive",
        value_token_index=1,
        reference_kind="proxy-section",
    ),
    StatementRule(
        keyword="use-server",
        kind="directive",
        value_token_index=1,
        reference_kind="server",
    ),
    StatementRule(
        keyword="default_backend",
        kind="directive",
        value_token_index=1,
        reference_kind="proxy-section",
    ),
    StatementRule(keyword="balance", kind="directive", value_token_index=1),
    StatementRule(keyword="mode", kind="directive", value_token_index=1),
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
