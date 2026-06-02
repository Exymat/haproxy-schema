from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re


@dataclass
class SampleFunctionInfo:
    name: str
    args: list[str] = field(default_factory=list)
    out_type: str = ""
    in_type: str = ""
    contexts: list[bool] = field(default_factory=list)


@dataclass
class DkallParseResult:
    section_keywords: dict[str, set[str]] = field(default_factory=dict)
    bind_options: set[str] = field(default_factory=set)
    server_options: set[str] = field(default_factory=set)
    options: set[str] = field(default_factory=set)
    http_request_actions: set[str] = field(default_factory=set)
    http_response_actions: set[str] = field(default_factory=set)
    http_after_response_actions: set[str] = field(default_factory=set)
    tcp_request_actions: set[str] = field(default_factory=set)
    tcp_response_actions: set[str] = field(default_factory=set)
    acl_criteria: set[str] = field(default_factory=set)
    sample_fetches: set[str] = field(default_factory=set)
    sample_converters: set[str] = field(default_factory=set)
    sample_fetches_structured: dict[str, SampleFunctionInfo] = field(default_factory=dict)
    sample_converters_structured: dict[str, SampleFunctionInfo] = field(default_factory=dict)
    filters: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)


_CONTEXT_RE = re.compile(r"^\[\s*([Y.\s]+)\]\s*(.+)$")
_FETCH_RE = re.compile(r"^([a-zA-Z0-9_.-]+)(?:\(([^)]*)\))?:\s*(\S+)")
_CONV_RE = re.compile(r"^([a-zA-Z0-9_.-]+)(?:\(([^)]*)\))?:\s*(\S+)\s*=>\s*(\S+)")


def _parse_blocks(lines: list[str]) -> dict[str, tuple[int, int]]:
    starts: list[tuple[str, int]] = []
    heading_re = re.compile(r"^# List of registered (.+):\s*$")
    for idx, line in enumerate(lines):
        m = heading_re.match(line.strip())
        if m:
            starts.append((m.group(1).strip().lower(), idx + 1))
    blocks: dict[str, tuple[int, int]] = {}
    for i, (name, start) in enumerate(starts):
        end = starts[i + 1][1] - 1 if i + 1 < len(starts) else len(lines)
        blocks[name] = (start, end)
    return blocks


def _last_significant_word(text: str) -> str | None:
    cleaned = _strip_dkall_arg_suffix(text)
    parts = cleaned.split()
    if not parts:
        return None
    return parts[-1].rstrip("*")


def _strip_dkall_arg_suffix(text: str) -> str:
    return re.sub(r"\s+\+[+-]?\d+\s*$", "", text.strip())


def _extract_option_tokens_after_prefix(entry: str, prefix: str) -> list[str]:
    if not entry.startswith(prefix):
        return []
    rest = _strip_dkall_arg_suffix(entry[len(prefix) :])
    tokens: list[str] = []
    for tok in rest.split():
        cleaned = tok.rstrip("*")
        if _is_significant_nested_token(cleaned):
            tokens.append(cleaned)
    return tokens


def _is_significant_nested_token(tok: str) -> bool:
    if not tok:
        return False
    if tok.startswith("<") and tok.endswith(">"):
        return False
    if tok in {"if", "unless"}:
        return False
    return True


def _parse_arg_types(arg_blob: str) -> list[str]:
    if not arg_blob.strip():
        return []
    out: list[str] = []
    for part in arg_blob.split(","):
        cleaned = part.strip().strip("[]")
        if cleaned:
            out.append(cleaned)
    return out


def _parse_context_flags(flags: str) -> list[bool]:
    return [ch == "Y" for ch in flags if ch in {"Y", "."}]


def _parse_fetch_line(line: str) -> SampleFunctionInfo | None:
    m_ctx = _CONTEXT_RE.match(line)
    body = line
    contexts: list[bool] = []
    if m_ctx:
        contexts = _parse_context_flags(m_ctx.group(1))
        body = m_ctx.group(2).strip()

    m = _FETCH_RE.match(body)
    if not m:
        return None
    return SampleFunctionInfo(
        name=m.group(1),
        args=_parse_arg_types(m.group(2) or ""),
        out_type=m.group(3),
        contexts=contexts,
    )


def _parse_converter_line(line: str) -> SampleFunctionInfo | None:
    line = line.strip()
    if line.startswith("[") and "]" in line:
        line = line.split("]", 1)[1].strip()
    m = _CONV_RE.match(line)
    if not m:
        return None
    return SampleFunctionInfo(
        name=m.group(1),
        args=_parse_arg_types(m.group(2) or ""),
        in_type=m.group(3),
        out_type=m.group(4),
    )


def _parse_cfg_block(lines: list[str], start: int, end: int, result: DkallParseResult) -> None:
    current_section = ""
    for raw in lines[start:end]:
        line = raw.rstrip("\n")
        if not line.strip():
            continue

        if not line.startswith((" ", "\t")):
            current_section = line.strip()
            result.section_keywords.setdefault(current_section, set())
            continue

        entry = line.strip()
        if not current_section:
            continue

        section_set = result.section_keywords.setdefault(current_section, set())

        if entry.startswith("bind <addr> "):
            section_set.add("bind")
            for word in _extract_option_tokens_after_prefix(entry, "bind <addr> "):
                result.bind_options.add(word)
            continue

        if entry.startswith("server <name> <addr> "):
            section_set.add("server")
            for word in _extract_option_tokens_after_prefix(entry, "server <name> <addr> "):
                result.server_options.add(word)
            continue

        if entry.startswith("option "):
            section_set.add("option")
            m = re.match(r"^option\s+([^\s]+)", entry)
            if m:
                result.options.add(m.group(1).rstrip("*"))
            continue

        if entry.startswith("http-request "):
            section_set.add("http-request")
            action = _last_significant_word(entry)
            if action:
                result.http_request_actions.add(action)
            continue

        if entry.startswith("http-response "):
            section_set.add("http-response")
            action = _last_significant_word(entry)
            if action:
                result.http_response_actions.add(action)
            continue

        if entry.startswith("http-after-response "):
            section_set.add("http-after-response")
            action = _last_significant_word(entry)
            if action:
                result.http_after_response_actions.add(action)
            continue

        if entry.startswith("tcp-request "):
            section_set.add("tcp-request")
            action = _last_significant_word(entry)
            if action:
                result.tcp_request_actions.add(action)
            continue

        if entry.startswith("tcp-response "):
            section_set.add("tcp-response")
            action = _last_significant_word(entry)
            if action:
                result.tcp_response_actions.add(action)
            continue

        if entry.startswith("filter "):
            section_set.add("filter")
            m = re.match(r"^filter\s+([^\s]+)", entry)
            if m:
                result.filters.add(m.group(1).rstrip("*"))
            continue

        keyword = entry.split()[0]
        section_set.add(keyword)


def _parse_acl_block(lines: list[str], start: int, end: int, result: DkallParseResult) -> None:
    for raw in lines[start:end]:
        line = raw.strip()
        if not line or "=" not in line:
            continue
        left = line.split("=", 1)[0].strip()
        if left:
            result.acl_criteria.add(left)


def _parse_fetch_block(lines: list[str], start: int, end: int, result: DkallParseResult) -> None:
    for raw in lines[start:end]:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        info = _parse_fetch_line(line)
        if not info:
            continue
        result.sample_fetches.add(info.name)
        result.sample_fetches_structured[info.name] = info


def _parse_converter_block(lines: list[str], start: int, end: int, result: DkallParseResult) -> None:
    for raw in lines[start:end]:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        info = _parse_converter_line(line)
        if not info:
            name = re.split(r"[\(:\s]", line, maxsplit=1)[0].strip()
            if name:
                result.sample_converters.add(name)
            continue
        result.sample_converters.add(info.name)
        result.sample_converters_structured[info.name] = info


def _parse_service_block(lines: list[str], start: int, end: int, result: DkallParseResult) -> None:
    for raw in lines[start:end]:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name = line.split()[0]
        if name:
            result.services.add(name)


def _parse_filter_block(lines: list[str], start: int, end: int, result: DkallParseResult) -> None:
    for raw in lines[start:end]:
        line = raw.strip()
        if not line:
            continue
        name = line.split()[0]
        result.filters.add(name)


def parse_dkall(path: Path) -> DkallParseResult:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if lines and lines[0].startswith("HAProxy version"):
        raise ValueError(
            f"{path} does not look like dkall output (got usage text). "
            "Build HAProxy with DEBUG=1 and run: haproxy -dKall -q"
        )
    blocks = _parse_blocks(lines)
    out = DkallParseResult()

    for name, (start, end) in blocks.items():
        if "configuration keywords" in name:
            _parse_cfg_block(lines, start, end, out)
        elif "acl keywords" in name:
            _parse_acl_block(lines, start, end, out)
        elif "sample fetch functions" in name:
            _parse_fetch_block(lines, start, end, out)
        elif "sample converter functions" in name:
            _parse_converter_block(lines, start, end, out)
        elif "filter names" in name:
            _parse_filter_block(lines, start, end, out)
        elif "service names" in name:
            _parse_service_block(lines, start, end, out)
    return out
