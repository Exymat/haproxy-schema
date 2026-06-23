"""Collect log-format (<fmt>) slot metadata from merged keyword signatures."""

from __future__ import annotations

from .schema import Keyword


def _emit(seen: set[tuple], slots: list[dict], kind: str, **fields: object) -> None:
    key = (kind, tuple(sorted((str(k), str(v)) for k, v in fields.items())))
    if key in seen:
        return
    seen.add(key)
    entry: dict[str, object] = {"kind": kind}
    entry.update(fields)
    slots.append(entry)


def _scan_signature(sig: str, seen: set[tuple], slots: list[dict]) -> None:
    sig = sig.strip()
    if "<fmt>" not in sig:
        return
    if not sig.endswith(" <fmt>"):
        return

    head = sig[: -len(" <fmt>")].strip()
    parts = head.split()
    if not parts:
        return

    if parts[0] in {"http-check", "tcp-check"} and len(parts) > 1:
        action = parts[1]
        if action.startswith("set-var-fmt"):
            _emit(seen, slots, "prefix", prefix="set-var-fmt", skip=0)
        elif action.endswith("-lf") or action in {"send-lf"}:
            _emit(seen, slots, "prefix", prefix=action.split("(")[0], skip=0)
        return

    placeholders = [part for part in parts[1:] if part.startswith("<") and part.endswith(">")]
    directive_base = parts[0].split("(")[0]
    if "(" in parts[0]:
        _emit(seen, slots, "prefix", prefix=directive_base, skip=0)
    elif placeholders:
        _emit(seen, slots, "line_tail", directive=directive_base, skip=len(placeholders))
    else:
        _emit(seen, slots, "line_tail", directive=directive_base, skip=0)


def _scan_parameter(parameter: str, seen: set[tuple], slots: list[dict]) -> None:
    param = parameter.strip()
    if "<fmt>" not in param:
        return
    parts = param.split()
    if not parts or parts[-1] != "<fmt>":
        return
    if len(parts) == 2:
        _emit(seen, slots, "prefix", prefix=parts[0], skip=0)
    elif len(parts) == 3 and parts[1] == "<name>":
        _emit(seen, slots, "prefix", prefix=parts[0], skip=1)


def collect_logformat_slots(keywords: dict[str, Keyword]) -> list[dict]:
    seen: set[tuple] = set()
    slots: list[dict] = []

    for keyword in keywords.values():
        sources: list[tuple[list[str], list]] = [
            (keyword.signatures, keyword.arguments),
        ]
        for variant in keyword.variants:
            sources.append((variant.signatures, variant.arguments))

        for signatures, arguments in sources:
            for signature in signatures or []:
                _scan_signature(signature, seen, slots)
            for argument in arguments or []:
                _scan_parameter(argument.parameter, seen, slots)

    for prefix in (
        "name-lf",
        "value-lf",
        "string-lf",
        "lf-string",
        "lf-file",
        "send-lf",
    ):
        _emit(seen, slots, "prefix", prefix=prefix, skip=0)

    return sorted(
        slots,
        key=lambda slot: (
            slot["kind"],
            str(slot.get("directive", "")),
            str(slot.get("prefix", "")),
            int(slot.get("skip", 0)),
        ),
    )
