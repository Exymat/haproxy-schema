"""Derive argument arity and positional enums from HAProxy keyword signatures."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Protocol

from .dconv_bridge import extract_keyword_name

_ENUM_RE = re.compile(r"^\{(.+)\}$")
_CONDITIONAL_TAIL = re.compile(r"^\[\s*\{\s*if\s*\|\s*unless\s*\}", re.I)
_VARIADIC_CATCHALLS = frozenset(
    {
        "param*",
        "params*",
        "arg*",
        "args*",
        "param...",
        "params...",
        "arg...",
        "args...",
    }
)
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


class _ValueDocLike(Protocol):
    name: str


class _ArgumentParamLike(Protocol):
    parameter: str
    values: list[_ValueDocLike]


class _KeywordLike(Protocol):
    signatures: list[str]
    arguments: list[_ArgumentParamLike]
    argument_model: object | None


def _find_matching(text: str, start: int, open_char: str, close_char: str) -> int:
    depth = 0
    for idx in range(start, len(text)):
        ch = text[idx]
        if ch == open_char:
            depth += 1
        elif ch == close_char:
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _tokenize_signature_parts(signature: str) -> list[str]:
    out: list[str] = []
    current: list[str] = []
    stack: list[str] = []
    closing = {"<": ">", "[": "]", "{": "}", "(": ")"}
    for ch in signature.strip():
        if ch.isspace() and not stack:
            if current:
                out.append("".join(current))
                current = []
            continue
        current.append(ch)
        if ch in closing:
            stack.append(closing[ch])
            continue
        if stack and ch == stack[-1]:
            stack.pop()
    if current:
        out.append("".join(current))
    return out


def _split_top_level(text: str, delimiter: str) -> list[str]:
    out: list[str] = []
    current: list[str] = []
    stack: list[str] = []
    closing = {"<": ">", "[": "]", "{": "}", "(": ")"}
    for ch in text:
        if ch == delimiter and not stack:
            piece = "".join(current).strip()
            if piece:
                out.append(piece)
            current = []
            continue
        current.append(ch)
        if ch in closing:
            stack.append(closing[ch])
            continue
        if stack and ch == stack[-1]:
            stack.pop()
    piece = "".join(current).strip()
    if piece:
        out.append(piece)
    return out


def _explode_token(token: str) -> list[str]:
    out: list[str] = []
    idx = 0
    while idx < len(token):
        ch = token[idx]
        if ch.isspace():
            idx += 1
            continue
        if ch in "<[{(":
            close = { "<": ">", "[": "]", "{": "}", "(": ")" }[ch]
            end = _find_matching(token, idx, ch, close)
            if end < 0:
                out.append(token[idx:])
                break
            piece = token[idx : end + 1]
            idx = end + 1
            if ch == "[":
                while idx < len(token) and token[idx] in {"*", "."}:
                    if token.startswith("...", idx):
                        piece += "..."
                        idx += 3
                    elif token[idx] == "*":
                        piece += "*"
                        idx += 1
                    else:
                        idx += 1
            out.append(piece)
            continue
        start = idx
        while idx < len(token) and token[idx] not in "<[{(":
            idx += 1
        literal = token[start:idx].strip()
        if literal:
            out.append(literal)
    return out


def _parse_enum_values(part: str) -> list[str]:
    match = _ENUM_RE.match(part.strip())
    if not match:
        return []
    values: list[str] = []
    for piece in _split_top_level(match.group(1), "|"):
        value = piece.strip()
        if not value or value.startswith("<"):
            continue
        if any(ch in value for ch in "<>[]{}()"):
            continue
        values.append(value.lower())
    return values


def _value_kind_from_part(part: str) -> str:
    lower = part.lower()
    if part.startswith("{"):
        return "enum"
    if lower in {"<name>", "<server-name>", "<id>", "<param>", "<parameter>"}:
        return "name"
    if lower in {"<thread-group>", "<thread-set>"}:
        return "name"
    if "addr" in lower or lower in {"<address>", "<addr>"}:
        return "address"
    if "path" in lower or "file" in lower:
        return "path"
    if "port" in lower:
        return "generic"
    return "generic"


def _literal_slot(part: str, *, optional: bool = False, variadic: bool = False) -> ArgSlot | None:
    cleaned = part.strip().strip(",").strip(":").strip("/")
    if not cleaned:
        return None
    if cleaned.startswith("(") and "<" in cleaned:
        return ArgSlot(optional=optional, variadic=variadic)
    if cleaned.lower() in _VARIADIC_CATCHALLS:
        return ArgSlot(optional=optional, variadic=True)
    if cleaned == "...":
        return ArgSlot(optional=optional, variadic=True)
    if (
        "|" in cleaned
        and "<" not in cleaned
        and "{" not in cleaned
        and "(" not in cleaned
        and "[" not in cleaned
    ):
        enum = [piece.strip().lower() for piece in _split_top_level(cleaned, "|") if piece.strip()]
        if len(enum) > 1:
            return ArgSlot(optional=optional, variadic=variadic, enum=enum, value_kind="enum")
    return ArgSlot(optional=optional, variadic=variadic, enum=[cleaned.lower()], value_kind="enum")


def _build_model_from_slots(slots: list[ArgSlot]) -> ArgumentModel | None:
    if not slots:
        return None
    if any(slot.variadic for slot in slots):
        required = sum(1 for slot in slots if not slot.optional and not slot.variadic)
        return ArgumentModel(min_args=required, max_args=None, slots=slots)
    required = sum(1 for slot in slots if not slot.optional)
    return ArgumentModel(min_args=required, max_args=len(slots), slots=slots)


def _parse_sequence(text: str) -> list[ArgSlot]:
    slots: list[ArgSlot] = []
    previous_part = ""
    for token in _tokenize_signature_parts(text):
        for part in _explode_token(token):
            if _is_port_decoration(part, previous_part):
                previous_part = part
                continue
            if part == "...":
                if slots:
                    slots[-1].variadic = True
                previous_part = part
                continue
            for slot in _parse_slot(part):
                if slot is not None:
                    slots.append(slot)
            previous_part = part
    return slots


def _parse_slot(part: str) -> list[ArgSlot]:
    part = part.strip()
    if not part:
        return []
    if _CONDITIONAL_TAIL.match(part):
        return []

    if part.startswith("{"):
        enum = _parse_enum_values(part)
        if enum:
            return [ArgSlot(enum=enum, value_kind="enum")]
        models: list[ArgumentModel] = []
        for alternative in _split_top_level(part[1:-1].strip(), "|"):
            model = _build_model_from_slots(_parse_sequence(alternative))
            if model is not None:
                models.append(model)
        merged = merge_argument_models(models)
        return list(merged.slots) if merged is not None else [ArgSlot()]

    if part.startswith("<") and part.endswith(">"):
        inner = part[1:-1].strip()
        kind = _value_kind_from_part(part)
        if inner.endswith("...") or inner.endswith("*"):
            return [ArgSlot(variadic=True, value_kind=kind)]
        return [ArgSlot(value_kind=kind)]

    if part.startswith("["):
        variadic = False
        if part.endswith("..."):
            core = part[:-3]
            variadic = True
        elif part.endswith("*"):
            core = part[:-1]
            variadic = True
        else:
            core = part
        inner = core[1:-1].strip() if core.endswith("]") else core[1:].strip()
        if _CONDITIONAL_TAIL.match(part) or inner.startswith("{ if"):
            return []
        if inner.startswith("{"):
            enum = _parse_enum_values(inner)
            if enum:
                return [ArgSlot(optional=True, variadic=variadic, enum=enum, value_kind="enum")]
            models: list[ArgumentModel] = []
            for alternative in _split_top_level(inner[1:-1].strip(), "|"):
                slots = _parse_sequence(alternative)
                for slot in slots:
                    slot.optional = True
                model = _build_model_from_slots(slots)
                if model is not None:
                    models.append(model)
            merged = merge_argument_models(models)
            if merged is not None:
                if variadic and merged.slots:
                    merged.slots[-1].variadic = True
                return list(merged.slots)
        if inner.lower() in _VARIADIC_CATCHALLS:
            return [ArgSlot(optional=True, variadic=True)]
        if (
            "|" in inner
            and "<" not in inner
            and "{" not in inner
            and "(" not in inner
            and not inner.startswith("[")
        ):
            enum = [piece.strip().lower() for piece in _split_top_level(inner, "|") if piece.strip()]
            if enum:
                return [ArgSlot(optional=True, variadic=variadic, enum=enum, value_kind="enum")]
        if (
            " " in inner
            and "<" not in inner
            and "{" not in inner
            and not inner.startswith("[")
        ):
            return [ArgSlot(optional=True)]
        slots: list[ArgSlot] = []
        for token in _tokenize_signature_parts(inner):
            for piece in _explode_token(token):
                child_slots = _parse_slot(piece)
                for slot in child_slots:
                    slot.optional = True
                    slots.append(slot)
        if variadic and slots:
            slots[-1].variadic = True
        if slots:
            return slots
        literal = _literal_slot(inner, optional=True, variadic=variadic)
        return [literal] if literal is not None else []

    if part in {",", "...", "(*)", "(deprecated)"} or part.startswith(","):
        return []

    literal = _literal_slot(part)
    return [literal] if literal is not None else []


def _signature_argument_parts(signature: str, keyword: str) -> list[str]:
    sig = re.sub(r"\s+\(deprecated\)$", "", signature.strip(), flags=re.I)
    if sig.lower().startswith(keyword.lower()):
        remainder = sig[len(keyword) :].strip()
        if remainder.startswith("("):
            end = _find_matching(remainder, 0, "(", ")")
            if end > 0:
                remainder = remainder[1:end] + remainder[end + 1 :]
        parts: list[str] = []
        for token in _tokenize_signature_parts(remainder):
            parts.extend(_explode_token(token))
        return parts
    parts = _tokenize_signature_parts(sig)
    kw_parts = keyword.split()
    if parts[: len(kw_parts)] == kw_parts:
        out: list[str] = []
        for token in parts[len(kw_parts) :]:
            out.extend(_explode_token(token))
        return out
    name = extract_keyword_name(signature)
    name_parts = name.split()
    if parts[: len(name_parts)] == name_parts:
        out: list[str] = []
        for token in parts[len(name_parts) :]:
            out.extend(_explode_token(token))
        return out
    out: list[str] = []
    for token in parts[len(kw_parts) :]:
        out.extend(_explode_token(token))
    return out


def _is_port_decoration(part: str, previous_part: str) -> bool:
    lower = part.strip().lower()
    prev = previous_part.strip().lower()
    if prev == ":" and lower.startswith("<port"):
        return True
    if lower.startswith("[") and "port" in lower and ":" in lower and "<" not in lower.split("port", 1)[0]:
        return True
    return False


def parse_signature_model(signature: str, keyword: str) -> ArgumentModel | None:
    parts = _signature_argument_parts(signature, keyword)
    if not parts:
        return ArgumentModel(min_args=0, max_args=0, slots=[])

    slots = _parse_sequence(" ".join(parts))

    if not slots:
        return None
    return _build_model_from_slots(slots)


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
        kinds: set[str] = set()
        seen = False
        for model in models:
            if idx >= len(model.slots):
                continue
            seen = True
            slot = model.slots[idx]
            optional = optional and slot.optional
            variadic = variadic or slot.variadic
            enums.update(slot.enum)
            if slot.value_kind:
                kinds.add(slot.value_kind)
        if not seen:
            continue
        value_kind = "generic"
        if enums:
            value_kind = "enum"
        elif len(kinds) == 1:
            value_kind = next(iter(kinds))
        elif "address" in kinds:
            value_kind = "address"
        elif "name" in kinds:
            value_kind = "name"
        elif "path" in kinds:
            value_kind = "path"
        merged_slots.append(
            ArgSlot(
                optional=optional,
                variadic=variadic,
                enum=sorted(enums),
                value_kind=value_kind,
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


def _enrich_slots_from_doc_enums(model: ArgumentModel, enum_names: list[str], slot_index: int = 0) -> None:
    if not enum_names or slot_index >= len(model.slots):
        return
    if model.slots[slot_index].enum:
        merged = sorted(set(model.slots[slot_index].enum) | {name.lower() for name in enum_names})
        model.slots[slot_index].enum = merged
        return
    if any(slot.enum for slot in model.slots[slot_index + 1 :]):
        # Keep explicit trailing enum slots (e.g. optional literal modifiers) untouched.
        return
    model.slots[slot_index].enum = sorted({name.lower() for name in enum_names})
    model.slots[slot_index].value_kind = "enum"


_SYSLOG_FACILITIES = (
    "kern",
    "user",
    "mail",
    "daemon",
    "auth",
    "syslog",
    "lpr",
    "news",
    "uucp",
    "cron",
    "auth2",
    "ftp",
    "ntp",
    "audit",
    "alert",
    "cron2",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
)

_SYSLOG_LEVELS = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")

_REDIRECT_OPTIONS = ("drop-query", "append-slash", "ignore-empty", "set-cookie", "clear-cookie")


def _patch_log_argument_model(model: ArgumentModel) -> None:
    """Attach syslog facility/level enums to the trailing positional slots."""
    if len(model.slots) < 3:
        return
    for slot in model.slots:
        if slot.enum == ["profile"]:
            slot.optional = True
    tail_enums = (_SYSLOG_FACILITIES, _SYSLOG_LEVELS, _SYSLOG_LEVELS)
    start = len(model.slots) - len(tail_enums)
    for offset, enum_values in enumerate(tail_enums):
        slot = model.slots[start + offset]
        slot.enum = list(enum_values)
        slot.value_kind = "enum"


def _patch_redirect_argument_model(model: ArgumentModel) -> None:
    """Allow redirect option keywords and their arguments before the condition."""
    if not model.slots:
        return
    prefix_slot = model.slots[0]
    model.slots = [
        prefix_slot,
        ArgSlot(optional=True, enum=["code"], value_kind="enum"),
        ArgSlot(optional=True, value_kind="generic"),
        ArgSlot(optional=True, variadic=True, value_kind="generic"),
    ]
    model.min_args = 2
    model.max_args = None


def _patch_source_argument_model(model: ArgumentModel) -> None:
    """Collapse usesrc value alternatives into one trailing slot (address or keyword)."""
    for idx, slot in enumerate(model.slots):
        if "usesrc" not in slot.enum:
            continue
        if idx + 2 >= len(model.slots):
            return
        enum_slot = model.slots[idx + 1]
        tail_slot = model.slots[idx + 2]
        if not enum_slot.enum or tail_slot.enum:
            return
        model.slots[idx + 1] = ArgSlot(
            optional=True,
            enum=list(enum_slot.enum),
            value_kind="address" if tail_slot.value_kind in {"address", "generic"} else tail_slot.value_kind,
        )
        del model.slots[idx + 2]
        if isinstance(model.max_args, int):
            model.max_args = len(model.slots)
        return


def _patch_argument_model(keyword: str, model: ArgumentModel) -> None:
    lower = keyword.lower()
    if lower == "log":
        _patch_log_argument_model(model)
    elif lower.startswith("redirect "):
        _patch_redirect_argument_model(model)
    elif lower == "source":
        _patch_source_argument_model(model)


def _attach_argument_model_to_target(
    keyword: str,
    target: _KeywordLike,
    *,
    all_keywords: set[str],
) -> None:
    from .schema import ArgumentModel as SchemaArgumentModel

    signatures = getattr(target, "signatures", None) or []
    model = build_argument_model(keyword, signatures, all_keywords=all_keywords)
    if model is None:
        return
    _patch_argument_model(keyword, model)
    arguments = getattr(target, "arguments", None) or []
    normalized_param_to_slot = {
        param.parameter.strip().lower(): idx
        for idx, param in enumerate(arguments)
        if idx < len(model.slots)
    }
    for idx, param in enumerate(arguments):
        doc_enums: list[str] = []
        for value in getattr(param, "values", []) or []:
            base = value.name.split("(", 1)[0]
            if base and "<" not in base and ">" not in base:
                doc_enums.append(base)
        if not doc_enums:
            continue
        target_idx = None
        parameter = getattr(param, "parameter", "").strip().lower()
        if parameter in {"", "<algorithm>"} and idx < len(model.slots):
            target_idx = idx
        elif parameter in normalized_param_to_slot:
            target_idx = normalized_param_to_slot[parameter]
        elif len(arguments) == 1 and len(model.slots) == 1:
            target_idx = 0
        if target_idx is not None:
            _enrich_slots_from_doc_enums(model, doc_enums, target_idx)
    target.argument_model = SchemaArgumentModel(
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


def _preferred_keyword_variant(keyword: _KeywordLike) -> _KeywordLike | None:
    variants = getattr(keyword, "variants", None) or []
    if not variants:
        return keyword
    for chapter in ("4.2", "3.1", "3.2", "3.3"):
        for variant in variants:
            if getattr(variant, "chapter", "") == chapter:
                return variant
    return variants[0]


def attach_argument_models(keywords: dict[str, _KeywordLike]) -> None:
    """Mutate schema Keyword objects in place (expects .signatures list)."""
    names = set(keywords.keys())
    for keyword, kw in keywords.items():
        variants = getattr(kw, "variants", None) or []
        if variants:
            for variant in variants:
                _attach_argument_model_to_target(keyword, variant, all_keywords=names)
            preferred = _preferred_keyword_variant(kw)
            if preferred is not None:
                kw.argument_model = getattr(preferred, "argument_model", None)
                kw.arguments = list(getattr(preferred, "arguments", None) or [])
            continue
        _attach_argument_model_to_target(keyword, kw, all_keywords=names)
