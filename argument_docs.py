"""Extract argument value documentation from configuration.txt keyword blocks."""

from __future__ import annotations

from dataclasses import dataclass, field
import re

from .dconv_bridge import (
    DESCRIPTION_STOP_PREFIXES,
    collect_signature_lines,
    is_description_stop_line,
    is_skippable_metadata_line,
    match_dconv_keyword_line,
)

_VALUE_LINE_RE = re.compile(
    r"^ {6}(\S+(?:\([^)]*\))?)\s{2,}(.*)$"
)
_PARAM_LINE_RE = re.compile(r"^ {4}<([^>]+)>\s")
_LITERAL_VALUE_LINE_RE = re.compile(r"^ {4}([a-z][a-z0-9_.-]*)\s{2,}(.*)$", re.I)
_ARGUMENTS_HEADER_RE = re.compile(r"^ {2}Arguments?\s*:\s*$", re.I)


@dataclass
class ArgumentValueDoc:
    name: str
    description: str = ""


@dataclass
class ArgumentParamDoc:
    parameter: str
    description: str = ""
    values: list[ArgumentValueDoc] = field(default_factory=list)


def _keyword_block_end(lines: list[str], header_idx: int) -> int:
    signatures, next_idx = collect_signature_lines(lines, header_idx)
    idx = next_idx
    while idx < len(lines):
        if match_dconv_keyword_line(lines[idx]):
            return idx
        if lines[idx].strip() and not lines[idx].startswith(" "):
            return idx
        if is_description_stop_line(lines[idx]) and lines[idx].strip().startswith("See also"):
            return idx
        idx += 1
    return len(lines)


def _find_arguments_start(lines: list[str], header_idx: int, end_idx: int) -> int:
    idx = header_idx + 1
    while idx < end_idx:
        line = lines[idx]
        if match_dconv_keyword_line(line):
            idx += 1
            continue
        if _ARGUMENTS_HEADER_RE.match(line):
            return idx
        stripped = line.strip()
        if stripped.startswith("Example") or stripped.startswith("See also"):
            break
        idx += 1
    return -1


def _append_value(values: list[ArgumentValueDoc], name: str, description: str) -> None:
    cleaned = name.strip()
    if not cleaned:
        return
    key = cleaned.lower()
    for existing in values:
        if existing.name.lower() == key:
            if description and not existing.description:
                existing.description = description
            return
    values.append(ArgumentValueDoc(name=cleaned, description=description.strip()))


def extract_argument_docs(lines: list[str], header_idx: int) -> list[ArgumentParamDoc]:
    end_idx = _keyword_block_end(lines, header_idx)
    args_start = _find_arguments_start(lines, header_idx, end_idx)
    if args_start < 0:
        return []

    params: list[ArgumentParamDoc] = []
    current: ArgumentParamDoc | None = None
    collecting_values = False

    idx = args_start + 1
    while idx < end_idx:
        line = lines[idx]
        stripped = line.strip()
        if not stripped:
            idx += 1
            continue
        if match_dconv_keyword_line(line):
            break
        if is_description_stop_line(line) and not stripped.lower().startswith("may be used"):
            if stripped.startswith("Example") or stripped.startswith("See also"):
                break

        value_match = _VALUE_LINE_RE.match(line)
        if value_match:
            name, desc = value_match.group(1), value_match.group(2).strip()
            if current is None:
                current = ArgumentParamDoc(parameter="")
            _append_value(current.values, name, desc)
            collecting_values = True
            idx += 1
            continue

        param_match = _PARAM_LINE_RE.match(line)
        if param_match:
            if current and (current.values or current.description):
                params.append(current)
            current = ArgumentParamDoc(parameter=f"<{param_match.group(1)}>")
            collecting_values = False
            idx += 1
            while idx < end_idx:
                cont = lines[idx]
                if not cont.strip():
                    break
                if _VALUE_LINE_RE.match(cont) or _PARAM_LINE_RE.match(cont):
                    break
                if cont.startswith("    ") and not cont.startswith("      "):
                    current.description += (" " if current.description else "") + cont.strip()
                    idx += 1
                    continue
                if "following" in cont.lower():
                    collecting_values = True
                    idx += 1
                    break
                if cont.startswith("      "):
                    break
                break
            continue

        literal_match = _LITERAL_VALUE_LINE_RE.match(line)
        if literal_match and not line.startswith("      "):
            name, desc = literal_match.group(1), literal_match.group(2).strip()
            if current and (current.values or current.description):
                params.append(current)
            current = ArgumentParamDoc(parameter=name)
            _append_value(current.values, name, desc)
            collecting_values = False
            idx += 1
            continue

        if current and collecting_values and line.startswith("                  "):
            if current.values:
                current.values[-1].description += " " + stripped
            idx += 1
            continue

        if current and current.values and line.startswith("      ") and not _VALUE_LINE_RE.match(line):
            if current.values[-1].description:
                current.values[-1].description += " " + stripped
            idx += 1
            continue

        idx += 1

    if current and (current.values or current.description or current.parameter):
        params.append(current)

    return params


def flatten_argument_values(params: list[ArgumentParamDoc]) -> list[ArgumentValueDoc]:
    seen: set[str] = set()
    flat: list[ArgumentValueDoc] = []
    for param in params:
        for value in param.values:
            key = value.name.lower()
            if key in seen:
                continue
            seen.add(key)
            flat.append(value)
    return flat


def enum_names_from_params(params: list[ArgumentParamDoc]) -> list[str]:
    names: list[str] = []
    for param in params:
        for value in param.values:
            base = value.name.split("(", 1)[0].lower()
            if base and base not in names:
                names.append(base)
    return names
