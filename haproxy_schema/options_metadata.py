"""Identify proxy/server options that take a value from signatures."""

from __future__ import annotations

import re


def _normalize_signature(signature: str) -> str:
    return re.sub(r"\s+\(deprecated\)$", "", signature.strip(), flags=re.I)


def option_takes_value(option: str, signatures: list[str]) -> bool:
    """Return True when signature forms indicate an argument after option name."""
    lower = option.lower()
    for signature in signatures:
        sig = _normalize_signature(signature)
        sig_lower = sig.lower()
        if sig_lower == lower:
            continue
        if not sig_lower.startswith(f"{lower} "):
            continue
        tail = sig[len(option) :].strip()
        if not tail:
            continue
        # Any explicit tail means this option form requires at least one value token.
        return True
    return False


def collect_options_with_value(options: list[str], signatures_by_option: dict[str, list[str]]) -> list[str]:
    return sorted(
        {
            opt
            for opt in options
            if option_takes_value(opt, signatures_by_option.get(opt.lower(), signatures_by_option.get(opt, [])))
        }
    )
