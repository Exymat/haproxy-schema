from __future__ import annotations

from pathlib import Path
import re
from typing import Any


ADDRESS_POLICY_SITES: dict[str, tuple[str, tuple[str, ...]]] = {
    "bind": ("src/cfgparse.c", "int str2listener("),
    "log": ("src/log.c", ("parse the target address", "LOG_TARGET_DGRAM")),
    "source": ("src/cfgparse-listen.c", '"source", "usesrc", "interface"'),
    "server": ("src/server.c", "several ways to check the port component"),
    "serverSource": ("src/server.c", 'Parse the "source" server keyword'),
    "serverUsesrc": ("src/server.c", 'strcmp(args[*cur_arg + 1], "clientip")'),
    "serverSocks4": ("src/server.c", 'Parse the "socks4" server keyword'),
    "tcpCheckAddr": ("src/tcpcheck.c", 'strcmp(args[cur_arg], "addr") == 0'),
}
ADDRESS_POLICY_SITES = {
    key: (relative, anchors if isinstance(anchors, tuple) else (anchors,))
    for key, (relative, anchors) in ADDRESS_POLICY_SITES.items()
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _initializer_after(text: str, marker: str) -> str:
    start = text.find(marker)
    if start < 0:
        return ""
    brace = text.find("{", start)
    if brace < 0:
        return ""
    depth = 0
    for idx in range(brace, len(text)):
        char = text[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1 : idx]
    return ""


def extract_sample_types(haproxy_root: Path) -> tuple[list[str], dict[str, Any]]:
    sample_c = haproxy_root / "src" / "sample.c"
    text = _read(sample_c)
    block = _initializer_after(text, "smp_to_type[SMP_TYPES]")
    values = re.findall(r"\[SMP_T_[A-Z0-9_]+\]\s*=\s*\"([^\"]+)\"", block)
    return values, {"origin": "extracted", "source": str(sample_c), "symbol": "smp_to_type"}


def extract_sample_casts(haproxy_root: Path) -> tuple[list[list[bool]], dict[str, Any]]:
    sample_c = haproxy_root / "src" / "sample.c"
    text = _read(sample_c)
    block = _initializer_after(text, "sample_casts[SMP_TYPES][SMP_TYPES]")
    rows: list[list[bool]] = []
    for match in re.finditer(r"/\*\s*(?:from:\s*)?[A-Z0-9_]+\s*\*/\s*\{([^{}]+)\}", block):
        cells = [cell.strip() for cell in match.group(1).split(",") if cell.strip()]
        rows.append([cell != "NULL" for cell in cells])
    return rows, {
        "origin": "extracted",
        "source": str(sample_c),
        "symbol": "sample_casts",
        "rule": "non-NULL matrix cells are legal casts; c_none is a no-op legal cast",
    }


def _str2sa_call_after(text: str, anchor: str) -> str:
    start = text.find(anchor)
    if start < 0:
        return ""
    call_start = text.find("str2sa_range(", start)
    if call_start < 0:
        return ""
    end = text.find(");", call_start)
    return text[call_start:end] if end >= 0 else ""


def _policy_from_flags(flags: str) -> dict[str, bool]:
    peer_port_mandatory_only = "SRV_PARSE_IN_PEER_SECTION" in flags and "PA_O_PORT_OFS" in flags
    return {
        "portOk": "PA_O_PORT_OK" in flags,
        "portMandatory": "PA_O_PORT_MAND" in flags and not peer_port_mandatory_only,
        "portRange": "PA_O_PORT_RANGE" in flags,
        "portOffset": "PA_O_PORT_OFS" in flags,
    }


def extract_address_policies(haproxy_root: Path) -> tuple[dict[str, dict[str, bool]], dict[str, Any]]:
    policies: dict[str, dict[str, bool]] = {}
    provenance: dict[str, Any] = {}
    for policy, (relative, anchors) in ADDRESS_POLICY_SITES.items():
        source = haproxy_root / relative
        text = _read(source)
        anchor = ""
        call = ""
        for candidate in anchors:
            call = _str2sa_call_after(text, candidate)
            if call:
                anchor = candidate
                break
        if not call:
            continue
        policies[policy] = _policy_from_flags(call)
        provenance[policy] = {
            "origin": "extracted",
            "source": str(source),
            "anchor": anchor,
            "symbol": "str2sa_range",
        }
    return policies, provenance


def _block_after(text: str, anchor: str, end_anchor: str | None = None) -> str:
    start = text.find(anchor)
    if start < 0:
        return ""
    if end_anchor is None:
        return text[start:]
    end = text.find(end_anchor, start + len(anchor))
    return text[start:end] if end >= 0 else text[start:]


def extract_cookie_modes(haproxy_root: Path) -> tuple[list[str], dict[str, Any]]:
    source = haproxy_root / "src" / "cfgparse-listen.c"
    block = _block_after(_read(source), 'strcmp(args[0], "cookie") == 0', "}/* end else if")
    modes = sorted(set(re.findall(r"strcmp\(args\[cur_arg\], \"([^\"]+)\"\)", block)))
    return modes, {"origin": "extracted", "source": str(source), "parser": "cookie"}


def extract_mysql_check_rule(haproxy_root: Path) -> tuple[dict[str, list[str]], dict[str, Any]]:
    source = haproxy_root / "src" / "tcpcheck.c"
    block = _block_after(_read(source), "proxy_parse_mysql_check_opt", "/* Parses the \"option httpchk\"")
    values = sorted(set(re.findall(r"strcmp\(args\[cur_arg(?:\+\d+)?\], \"([^\"]+)\"\)", block)))
    modes = sorted(value for value in values if value != "user")
    return {"values": values, "modes": modes}, {
        "origin": "extracted",
        "source": str(source),
        "parser": "proxy_parse_mysql_check_opt",
    }


def extract_http_send_name_header_rule(haproxy_root: Path, version: str) -> tuple[dict[str, Any], dict[str, Any]]:
    source = haproxy_root / "src" / "cfgparse-listen.c"
    block = _block_after(_read(source), 'strcmp(args[0], "http-send-name-header") == 0', 'else if (strcmp(args[0], "block")')
    forbidden = sorted(set(re.findall(r"strcasecmp\(args\[1\], \"([^\"]+)\"\)", block)))
    return {"forbidden_first_arg_by_min_version": {version: forbidden} if forbidden else {}}, {
        "origin": "extracted",
        "source": str(source),
        "parser": "http-send-name-header",
    }


def extract_sample_min_args(haproxy_root: Path) -> tuple[dict[str, int], dict[str, int], dict[str, Any]]:
    fetch_names = {"payload_lv", "req.payload_lv", "res.payload_lv"}
    converter_prefixes = ("map",)
    converter_names = {"ipmask"}
    fetches: dict[str, int] = {}
    converters: dict[str, int] = {}
    provenance: dict[str, Any] = {}
    for relative in ("src/payload.c", "src/sample.c", "src/map.c"):
        source = haproxy_root / relative
        text = _read(source)
        for match in re.finditer(r'\{\s*"([^"]+)"\s*,[^\n{]*?\bARG\d+\((\d+),', text):
            name = match.group(1)
            min_args = int(match.group(2))
            if name in fetch_names:
                fetches[name] = min_args
                provenance[f"fetch_min_args.{name}"] = {
                    "origin": "extracted",
                    "source": str(source),
                    "symbol": name,
                }
            if name in converter_names or any(name.startswith(prefix) for prefix in converter_prefixes):
                converters[name] = min_args
                provenance[f"converter_min_args.{name}"] = {
                    "origin": "extracted",
                    "source": str(source),
                    "symbol": name,
                }
    return fetches, converters, provenance
