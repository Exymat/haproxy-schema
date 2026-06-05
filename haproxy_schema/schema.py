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
class Keyword:
    name: str
    sections: list[str] = field(default_factory=list)
    signatures: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    argument_model: ArgumentModel | None = None
    arguments: list[ArgumentParamDoc] = field(default_factory=list)


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
class HaproxySchema:
    version: str
    sections: dict[str, Section] = field(default_factory=dict)
    keywords: dict[str, Keyword] = field(default_factory=dict)
    keyword_groups: dict[str, list[str]] = field(default_factory=dict)
    statement_rules: list[StatementRule] = field(default_factory=list)
    sample_fetches: dict[str, SampleFunction] = field(default_factory=dict)
    sample_converters: dict[str, SampleFunction] = field(default_factory=dict)
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
            keywords[name] = Keyword(
                name=kw.get("name", name),
                sections=kw.get("sections", []),
                signatures=kw.get("signatures", []),
                sources=kw.get("sources", []),
                argument_model=argument_model,
                arguments=arguments,
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
                )
            return out

        return cls(
            version=data.get("version", "unknown"),
            sections=sections,
            keywords=keywords,
            keyword_groups=data.get("keyword_groups", {}),
            statement_rules=statement_rules,
            sample_fetches=_load_sample_funcs(data.get("sample_fetches", {})),
            sample_converters=_load_sample_funcs(data.get("sample_converters", {})),
            line_layout=data.get("line_layout", {}),
            tokens=data.get("tokens", {}),
        )

    @classmethod
    def from_json(cls, raw: str) -> "HaproxySchema":
        return cls.from_json_dict(json.loads(raw))

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json() + "\n", encoding="utf-8")
