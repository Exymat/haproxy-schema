from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any


@dataclass
class ArgumentModel:
    min_args: int = 0
    max_args: int | None = None
    slots: list[dict] = field(default_factory=list)


@dataclass
class ArgumentValueDoc:
    name: str
    description: str = ""


@dataclass
class ArgumentParamDoc:
    parameter: str
    description: str = ""
    values: list[ArgumentValueDoc] = field(default_factory=list)


@dataclass
class KeywordVariant:
    chapter: str = ""
    sections: list[str] = field(default_factory=list)
    contexts: list[str] = field(default_factory=list)
    signatures: list[str] = field(default_factory=list)
    argument_model: ArgumentModel | None = None
    arguments: list[ArgumentParamDoc] = field(default_factory=list)


@dataclass
class LineOptionSemantic:
    parent_kind: str
    option_group: str
    chapter: str
    takes_value: bool = False


@dataclass
class Keyword:
    name: str
    sections: list[str] = field(default_factory=list)
    contexts: list[str] = field(default_factory=list)
    signatures: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    variants: list[KeywordVariant] = field(default_factory=list)
    argument_model: ArgumentModel | None = None
    arguments: list[ArgumentParamDoc] = field(default_factory=list)
    line_option_semantics: list[LineOptionSemantic] = field(default_factory=list)


@dataclass
class Section:
    name: str
    keywords: list[str] = field(default_factory=list)


@dataclass
class SampleFunction:
    name: str
    args: list[str] = field(default_factory=list)
    out_type: str = ""
    in_type: str = ""
    contexts: list[bool] = field(default_factory=list)
    min_args: int | None = None
    max_args: int | None = None
    signature: str = ""
    description: str = ""
    chapter: str = ""
    deprecated: bool = False


@dataclass
class LogformatAlias:
    name: str
    field_name: str = ""
    sample_fetch: str = ""
    type: str = ""
    restrictions: str = ""
    category: str = ""


@dataclass
class FixedSlotSpec:
    role: str
    port: str | None = None
    address_policy: str | None = None


@dataclass
class StatementRule:
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


@dataclass
class ReferencePattern:
    match_tokens: list[str]
    reference_kind: str
    target_token_index: int
    scope: str = "global"
    split: str | None = None


@dataclass
class HaproxySchema:
    version: str
    sections: dict[str, Section] = field(default_factory=dict)
    keywords: dict[str, Keyword] = field(default_factory=dict)
    address_policies: dict[str, dict[str, bool]] = field(default_factory=dict)
    sample_types: list[str] = field(default_factory=list)
    sample_casts: list[list[bool]] = field(default_factory=list)
    symbols: dict[str, Any] = field(default_factory=dict)
    semantic_groups: dict[str, Any] = field(default_factory=dict)
    validation_rules: dict[str, Any] = field(default_factory=dict)
    keyword_groups: dict[str, list[str]] = field(default_factory=dict)
    keyword_group_contexts: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    statement_rules: list[StatementRule] = field(default_factory=list)
    reference_patterns: list[ReferencePattern] = field(default_factory=list)
    sample_fetches: dict[str, SampleFunction] = field(default_factory=dict)
    sample_converters: dict[str, SampleFunction] = field(default_factory=dict)
    logformat_aliases: dict[str, LogformatAlias] = field(default_factory=dict)
    logformat_slots: list[dict[str, object]] = field(default_factory=list)
    line_layout: dict[str, object] = field(default_factory=dict)
    tokens: dict[str, list[str]] = field(
        default_factory=lambda: {
            "modifiers": ["no", "default"],
            "conditionals": ["if", "unless"],
            "macros": [
                ".if",
                ".elif",
                ".else",
                ".endif",
                ".diag",
                ".notice",
                ".warning",
                ".alert",
            ],
            "no_prefix_keywords": [],
            "named_defaults_keywords": [],
        }
    )

    def to_json_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_json_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_json_dict(cls, data: dict[str, Any]) -> "HaproxySchema":
        sections = {
            name: Section(name=sec.get("name", name), keywords=sec.get("keywords", []))
            for name, sec in data.get("sections", {}).items()
        }
        keywords = {}
        for name, kw in data.get("keywords", {}).items():
            arg_raw = kw.get("argument_model")
            argument_model = None
            if arg_raw:
                argument_model = ArgumentModel(
                    min_args=arg_raw.get("min_args", 0),
                    max_args=arg_raw.get("max_args"),
                    slots=arg_raw.get("slots", []),
                )
            args_raw = kw.get("arguments", [])
            arguments = [
                ArgumentParamDoc(
                    parameter=param.get("parameter", ""),
                    description=param.get("description", ""),
                    values=[
                        ArgumentValueDoc(name=value.get("name", ""), description=value.get("description", ""))
                        for value in param.get("values", [])
                    ],
                )
                for param in args_raw
            ]
            variants_raw = kw.get("variants", [])
            variants = []
            for variant in variants_raw:
                variant_arg_raw = variant.get("argument_model")
                variant_argument_model = None
                if variant_arg_raw:
                    variant_argument_model = ArgumentModel(
                        min_args=variant_arg_raw.get("min_args", 0),
                        max_args=variant_arg_raw.get("max_args"),
                        slots=variant_arg_raw.get("slots", []),
                    )
                variant_args_raw = variant.get("arguments", [])
                variants.append(
                    KeywordVariant(
                        chapter=variant.get("chapter", ""),
                        sections=variant.get("sections", []),
                        contexts=variant.get("contexts", []),
                        signatures=variant.get("signatures", []),
                        argument_model=variant_argument_model,
                        arguments=[
                            ArgumentParamDoc(
                                parameter=param.get("parameter", ""),
                                description=param.get("description", ""),
                                values=[
                                    ArgumentValueDoc(
                                        name=value.get("name", ""),
                                        description=value.get("description", ""),
                                    )
                                    for value in param.get("values", [])
                                ],
                            )
                            for param in variant_args_raw
                        ],
                    )
                )
            keywords[name] = Keyword(
                name=kw.get("name", name),
                sections=kw.get("sections", []),
                contexts=kw.get("contexts", []),
                signatures=kw.get("signatures", []),
                sources=kw.get("sources", []),
                variants=variants,
                argument_model=argument_model,
                arguments=arguments,
                line_option_semantics=[
                    LineOptionSemantic(
                        parent_kind=item.get("parent_kind", ""),
                        option_group=item.get("option_group", ""),
                        chapter=item.get("chapter", ""),
                        takes_value=item.get("takes_value", False),
                    )
                    for item in kw.get("line_option_semantics", [])
                ],
            )
        statement_rules = []
        for rule in data.get("statement_rules", []):
            fixed_raw = rule.get("fixed_slots", [])
            fixed_slots = [
                FixedSlotSpec(
                    role=slot.get("role", ""),
                    port=slot.get("port"),
                    address_policy=slot.get("address_policy"),
                )
                for slot in fixed_raw
            ]
            statement_rules.append(
                StatementRule(
                    keyword=rule.get("keyword", ""),
                    kind=rule.get("kind", ""),
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

        reference_patterns = [
            ReferencePattern(
                match_tokens=item.get("match_tokens", []),
                reference_kind=item.get("reference_kind", ""),
                target_token_index=item.get("target_token_index", 0),
                scope=item.get("scope", "global"),
                split=item.get("split"),
            )
            for item in data.get("reference_patterns", [])
        ]

        def _load_sample_funcs(raw: dict[str, Any]) -> dict[str, SampleFunction]:
            out: dict[str, SampleFunction] = {}
            for name, item in raw.items():
                out[name] = SampleFunction(
                    name=item.get("name", name),
                    args=item.get("args", []),
                    out_type=item.get("out_type", ""),
                    in_type=item.get("in_type", ""),
                    contexts=item.get("contexts", []),
                    min_args=item.get("min_args"),
                    max_args=item.get("max_args"),
                    signature=item.get("signature", ""),
                    description=item.get("description", ""),
                    chapter=item.get("chapter", ""),
                    deprecated=item.get("deprecated", False),
                )
            return out

        def _load_logformat_aliases(raw: dict[str, Any]) -> dict[str, LogformatAlias]:
            out: dict[str, LogformatAlias] = {}
            for name, item in raw.items():
                out[name] = LogformatAlias(
                    name=item.get("name", name),
                    field_name=item.get("field_name", ""),
                    sample_fetch=item.get("sample_fetch", ""),
                    type=item.get("type", ""),
                    restrictions=item.get("restrictions", ""),
                    category=item.get("category", ""),
                )
            return out

        return cls(
            version=data.get("version", "unknown"),
            sections=sections,
            keywords=keywords,
            address_policies=data.get("address_policies", {}),
            sample_types=data.get("sample_types", []),
            sample_casts=data.get("sample_casts", []),
            symbols=data.get("symbols", {}),
            semantic_groups=data.get("semantic_groups", {}),
            validation_rules=data.get("validation_rules", {}),
            keyword_groups=data.get("keyword_groups", {}),
            keyword_group_contexts=data.get("keyword_group_contexts", {}),
            statement_rules=statement_rules,
            reference_patterns=reference_patterns,
            sample_fetches=_load_sample_funcs(data.get("sample_fetches", {})),
            sample_converters=_load_sample_funcs(data.get("sample_converters", {})),
            logformat_aliases=_load_logformat_aliases(data.get("logformat_aliases", {})),
            logformat_slots=data.get("logformat_slots", []),
            line_layout=data.get("line_layout", {}),
            tokens=data.get("tokens", {}),
        )

    @classmethod
    def from_json(cls, raw: str) -> "HaproxySchema":
        return cls.from_json_dict(json.loads(raw))

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json() + "\n", encoding="utf-8")
