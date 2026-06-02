"""Derive fixed positional slots from HAProxy keyword signatures (configuration.txt)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_SIGNATURE_PART_RE = re.compile(r"\{[^{}]*\}|<[^>]+>|\[[^\]]*\]|[^\s]+")


@dataclass
class FixedSlot:
    """One positional argument before nested keyword options."""

    role: str
    port: str | None = None  # required | optional | forbidden


@dataclass
class StatementLayout:
    keyword: str
    fixed_slots: list[FixedSlot] = field(default_factory=list)
    nested_start_index: int | None = None
    nested_group: str | None = None


def _tokenize_signature_parts(signature: str) -> list[str]:
    return _SIGNATURE_PART_RE.findall(signature.strip())


def _signature_argument_parts(signature: str, keyword: str) -> list[str]:
    parts = _tokenize_signature_parts(signature)
    kw_parts = keyword.split()
    if parts[: len(kw_parts)] == kw_parts:
        return parts[len(kw_parts) :]
    return parts[len(kw_parts) :]


def _port_policy_from_parts(parts: list[str], idx: int) -> str | None:
    """Infer port requirement from signature tokens after an <address> slot."""
    tail = " ".join(parts[idx + 1 :]).lower()
    if ":<port" in tail or "]:<port" in tail or "<port_range>" in tail:
        if "[[" in tail or "optional" in tail:
            return "optional"
        return "required"
    if "[:[port]]" in tail or "[port]" in tail:
        return "optional"
    return "optional"


def _role_from_placeholder(part: str) -> str | None:
    lower = part.lower()
    if lower in {"<name>", "<server-name>", "<id>"}:
        return "name"
    if lower in {"<address>", "<addr>"}:
        return "address"
    if lower.startswith("/"):
        return "address_unix"
    return None


def layout_from_signature(keyword: str, signature: str) -> StatementLayout | None:
    parts = _signature_argument_parts(signature, keyword)
    if not parts:
        return None

    slots: list[FixedSlot] = []
    for idx, part in enumerate(parts):
        if part.startswith("[") and ("param" in part.lower() or "..." in part):
            break
        if part in {",", "...", "(*)", "(deprecated)"} or part.startswith(","):
            continue
        role = _role_from_placeholder(part)
        if role == "address_unix":
            slots.append(FixedSlot(role="address", port="forbidden"))
            continue
        if role == "address":
            slots.append(FixedSlot(role="address", port=_port_policy_from_parts(parts, idx)))
            continue
        if role == "name":
            slots.append(FixedSlot(role="name"))
            continue
        if part.startswith("<") and part.endswith(">"):
            slots.append(FixedSlot(role="value"))
            continue

    if not slots:
        return None

    nested_start = 1 + len(slots)
    group = None
    if keyword == "bind":
        group = "bind_options"
    elif keyword == "server":
        group = "server_options"

    return StatementLayout(
        keyword=keyword,
        fixed_slots=slots,
        nested_start_index=nested_start,
        nested_group=group,
    )


def pick_best_layout(keyword: str, signatures: list[str]) -> StatementLayout | None:
    layouts = [layout_from_signature(keyword, sig) for sig in signatures]
    layouts = [layout for layout in layouts if layout and layout.fixed_slots]
    if not layouts:
        return None
    # Prefer layouts with address slots (more specific than generic <param*> only).
    layouts.sort(key=lambda layout: (sum(1 for s in layout.fixed_slots if s.role == "address"), len(layout.fixed_slots)), reverse=True)
    return layouts[0]


def fixed_slots_to_dict(slots: list[FixedSlot]) -> list[dict]:
    return [{"role": slot.role, "port": slot.port} for slot in slots]


def _keyword_signatures(keywords: dict, name: str) -> list[str]:
    kw = keywords.get(name)
    if kw is None:
        return []
    if isinstance(kw, dict):
        return list(kw.get("signatures", []))
    return list(getattr(kw, "signatures", []))


def enrich_statement_rules(rules: list[dict], keywords: dict) -> list[dict]:
    """Attach fixed_slots to statement_rules entries when signatures define them."""
    by_keyword: dict[str, dict] = {rule["keyword"]: rule for rule in rules}
    for layout_keyword in ("server", "bind", "nameserver"):
        signatures = _keyword_signatures(keywords, layout_keyword)
        layout = pick_best_layout(layout_keyword, signatures)
        if not layout:
            continue
        rule = by_keyword.get(layout_keyword)
        if not rule:
            continue
        rule["fixed_slots"] = fixed_slots_to_dict(layout.fixed_slots)
        if layout.nested_start_index is not None:
            rule["nested_start_index"] = layout.nested_start_index
        if layout.nested_group and not rule.get("group"):
            rule["group"] = layout.nested_group
    return list(by_keyword.values())
