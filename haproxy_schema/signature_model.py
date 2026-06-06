"""Derive argument arity and positional enums from HAProxy keyword signatures."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Protocol

from .dconv_bridge import extract_keyword_name

_ENUM_RE = re.compile(r"^\{(.+)\}$")
_CONDITIONAL_TAIL = re.compile(r"^\[\s*\{\s*if\s*\|\s*unless\s*\}", re.I)


@dataclass
class ArgSlot:
    optional: bool = False
    variadic: bool = False
    enum: list[str] = field(default_factory=list)
    value_kind: str = "generic"


@dataclass
class ArgumentModel:
    min_args: int = 0
    max_args: int | None = None
    slots: list[ArgSlot] = field(default_factory=list)

    def to_json_dict(self) -> dict:
        return asdict(self)


_SIGNATURE_PART_RE = re.compile(r"\{[^{}]*\}|<[^>]+>|\[[^\]]*\]|[^\s]+")


class _ValueDocLike(Protocol):
    name: str


class _ArgumentParamLike(Protocol):
    parameter: str
    values: list[_ValueDocLike]


class _KeywordLike(Protocol):
    signatures: list[str]
    arguments: list[_ArgumentParamLike]
    argument_model: object | None


def _tokenize_signature_parts(signature: str) -> list[str]:
    return _SIGNATURE_PART_RE.findall(signature.strip())


def _parse_enum_values(part: str) -> list[str]:
    match = _ENUM_RE.match(part.strip())
    if not match:
        return []
    values: list[str] = []
    for piece in match.group(1).split("|"):
        value = piece.strip()
        if not value or value.startswith("<"):
            continue
        values.append(value.lower())
    return values


def _value_kind_from_part(part: str) -> str:
    lower = part.lower()
    if part.startswith("{"):
        return "enum"
    if lower in {"<name>", "<server-name>", "<id>"}:
        return "name"
    if "addr" in lower or lower in {"<address>", "<addr>"}:
        return "address"
    if "path" in lower or "file" in lower:
        return "path"
    return "generic"


def _parse_slot(part: str) -> ArgSlot | None:
    part = part.strip()
    if not part:
        return None
    if _CONDITIONAL_TAIL.match(part):
        return None

    if part.startswith("{"):
        enum = _parse_enum_values(part)
        if enum:
            return ArgSlot(enum=enum, value_kind="enum")
        return ArgSlot()

    if part.startswith("<") and part.endswith(">"):
        inner = part[1:-1].strip()
        kind = _value_kind_from_part(part)
        if inner.endswith("...") or inner.endswith("*"):
            return ArgSlot(variadic=True, value_kind=kind)
        return ArgSlot(value_kind=kind)

    if part.startswith("["):
        inner = part[1:-1].strip() if part.endswith("]") else part[1:].strip()
        if _CONDITIONAL_TAIL.match(part) or inner.startswith("{ if"):
            return None
        if "..." in inner or inner.endswith("*"):
            return ArgSlot(optional=True, variadic=True)
        if inner.startswith("{"):
            enum = _parse_enum_values(inner)
            if enum:
                return ArgSlot(optional=True, enum=enum, value_kind="enum")
        if inner.startswith("<"):
            return ArgSlot(optional=True, value_kind=_value_kind_from_part(inner if inner.startswith("<") else f"<{inner}>"))
        return ArgSlot(optional=True)

    if part in {",", "...", "(*)", "(deprecated)"} or part.startswith(","):
        return None

    # Literal token in the signature (e.g. "meth", "send") counts as a required argument.
    return ArgSlot()


def _signature_argument_parts(signature: str, keyword: str) -> list[str]:
    parts = _tokenize_signature_parts(signature)
    kw_parts = keyword.split()
    if parts[: len(kw_parts)] == kw_parts:
        return parts[len(kw_parts) :]
    name = extract_keyword_name(signature)
    name_parts = name.split()
    if parts[: len(name_parts)] == name_parts:
        return parts[len(name_parts) :]
    return parts[len(kw_parts) :]


def parse_signature_model(signature: str, keyword: str) -> ArgumentModel | None:
    parts = _signature_argument_parts(signature, keyword)
    if not parts:
        return ArgumentModel(min_args=0, max_args=0, slots=[])

    slots: list[ArgSlot] = []
    for part in parts:
        if part == "...":
            if slots:
                slots[-1].variadic = True
            continue
        slot = _parse_slot(part)
        if slot is not None:
            slots.append(slot)

    if not slots:
        return None

    if any(slot.variadic for slot in slots):
        required = sum(1 for slot in slots if not slot.optional and not slot.variadic)
        return ArgumentModel(min_args=required, max_args=None, slots=slots)

    required = sum(1 for slot in slots if not slot.optional)
    return ArgumentModel(min_args=required, max_args=len(slots), slots=slots)


def merge_argument_models(models: list[ArgumentModel]) -> ArgumentModel | None:
    if not models:
        return None
    if len(models) == 1:
        return models[0]

    any_variadic = any(m.max_args is None for m in models)
    merged_max: int | None = None if any_variadic else max(m.max_args or 0 for m in models)
    merged_min = min(m.min_args for m in models)

    max_len = max(len(m.slots) for m in models)
    merged_slots: list[ArgSlot] = []
    for idx in range(max_len):
        optional = True
        variadic = False
        enums: set[str] = set()
        seen = False
        for model in models:
            if idx >= len(model.slots):
                continue
            seen = True
            slot = model.slots[idx]
            optional = optional and slot.optional
            variadic = variadic or slot.variadic
            enums.update(slot.enum)
        if not seen:
            continue
        merged_slots.append(
            ArgSlot(
                optional=optional,
                variadic=variadic,
                enum=sorted(enums),
                value_kind="enum" if enums else "generic",
            )
        )

    return ArgumentModel(min_args=merged_min, max_args=merged_max, slots=merged_slots)


def build_argument_model(
    keyword: str,
    signatures: list[str],
    *,
    all_keywords: set[str] | None = None,
) -> ArgumentModel | None:
    filtered = list(signatures)
    if all_keywords and any(name != keyword and name.startswith(f"{keyword} ") for name in all_keywords):
        filtered = [sig for sig in filtered if sig.strip().lower() != keyword.lower()]

    models: list[ArgumentModel] = []
    for signature in filtered:
        model = parse_signature_model(signature, keyword)
        if model is not None:
            models.append(model)
    return merge_argument_models(models)


def _enrich_slots_from_doc_enums(model: ArgumentModel, enum_names: list[str]) -> None:
    if not enum_names:
        return
    for slot in model.slots:
        if slot.enum:
            merged = sorted(set(slot.enum) | {name.lower() for name in enum_names})
            slot.enum = merged
            return
    if model.slots:
        model.slots[0].enum = sorted({name.lower() for name in enum_names})


def attach_argument_models(keywords: dict[str, _KeywordLike]) -> None:
    """Mutate schema Keyword objects in place (expects .signatures list)."""
    from .schema import ArgumentModel as SchemaArgumentModel

    names = set(keywords.keys())
    for keyword, kw in keywords.items():
        signatures = getattr(kw, "signatures", None) or []
        model = build_argument_model(keyword, signatures, all_keywords=names)
        if model is None:
            continue
        doc_enums: list[str] = []
        arguments = getattr(kw, "arguments", None) or []
        for param in arguments:
            if param.parameter not in ("", "<algorithm>"):
                continue
            for value in getattr(param, "values", []) or []:
                base = value.name.split("(", 1)[0]
                if base:
                    doc_enums.append(base)
        _enrich_slots_from_doc_enums(model, doc_enums)
        kw.argument_model = SchemaArgumentModel(
            min_args=model.min_args,
            max_args=model.max_args,
            slots=[
                {
                    "optional": slot.optional,
                    "variadic": slot.variadic,
                    "enum": list(slot.enum),
                    "value_kind": slot.value_kind,
                }
                for slot in model.slots
            ],
        )
