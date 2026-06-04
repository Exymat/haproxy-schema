"""Build a complete TextMate grammar from HaproxySchema (minimal hand-written rules)."""

from __future__ import annotations

import re
from typing import Any

from .grammar_util import (
    alt_pattern,
    collect_cache_keywords,
    collect_directive_keywords,
    is_directive_token,
    action_words,
)
from .schema import HaproxySchema

_DIRECTIVE = "keyword.other.directive.haproxy"
_MODIFIER = "keyword.other.modifier.haproxy"
_OPTION = "keyword.other.option.haproxy"
_SECTION = "entity.name.type.section.haproxy"
# frontend/backend/listen/defaults profile and named section labels (Cursor Dark:
# entity.name.type.class → #87c3ff).
_PROXY_LABEL = "entity.name.type.class.proxy.haproxy"
# server / cookie / from target / other identifier-like names (Cursor Dark: entity.name.type → #efb080).
_PROXY = "entity.name.type.proxy.haproxy"
# ACL names (Cursor Dark: entity.other.attribute-name → #aaa0fa).
_ACL_NAME = "entity.other.attribute-name.acl.haproxy"
_STRING = "string.unquoted.haproxy"
_NUMBER = "constant.numeric.haproxy"
_STORAGE = "storage.type"
_COMMENT = "comment.line.number-sign.haproxy"
_PREPROCESSOR = "keyword.control.preprocessor.haproxy"

_TCP_PHASES = ("connection", "session", "content", "inspect-delay")

_RULE_KEYWORDS = (
    "http-request",
    "http-response",
    "http-after-response",
    "tcp-request",
    "tcp-response",
)

_HEADER_ACTIONS = ("add-header", "set-header", "del-header", "replace-header")

_EXPECT_TYPES = (
    "status",
    "binary",
    "string",
    "rstring",
    "lstring",
    "comment",
    "hdr",
    "unique-id-id",
    "unique-id-counters",
    "http-version",
    "ssl",
    "alpn",
    "npn",
    "proto",
    "method",
    "uri",
    "body",
    "header",
    "cookie",
    "var",
    "env",
    "proc",
    "sess",
    "be",
    "fe",
    "src",
    "dst",
    "bytes",
    "date",
    "rand",
    "uuid",
)

_BIND_TAIL_INCLUDES = [
    {"include": "#comments"},
    {"include": "#bind-param-pairs"},
    {"include": "#addresses"},
    {"include": "#strings"},
    {"include": "#numbers"},
]

_VALUE_OPTION_HINTS = (
    "-file",
    "-path",
    "-pass",
    "-list",
    "-addr",
    "-port",
    "-net",
    "-opts",
    "-prefer",
    "-name",
    "-tag",
    "-format",
    "-header",
    "-backend",
    "-server",
    "-conn",
    "-delay",
    "-limit",
    "-inter",
    "-key",
)

_VALUE_OPTION_EXACT = frozenset(
    {
        "crt",
        "name",
        "alpn",
        "ciphers",
        "ciphersuites",
        "curves",
        "npn",
        "proto",
        "verify",
        "verifyhost",
        "sni",
        "mss",
        "nbconn",
        "nice",
        "uid",
        "gid",
        "group",
        "interface",
        "namespace",
        "thread",
        "process",
        "shards",
        "sigalgs",
        "addr",
        "path",
        "command",
        "redir",
        "resolvers",
        "weight",
        "port",
        "mode",
        "level",
        "label",
        "id",
        "ws",
        "shard",
        "hash-key",
        "monitor",
        "description",
        "agent-port",
        "agent-inter",
        "agent-send",
        "pool-max-conn",
        "pool-low-conn",
        "pool-purge-delay",
        "pool-conn-name",
        "log-proto",
        "log-bufsize",
        "max-reuse",
        "slowstart",
        "maxqueue",
        "minconn",
        "maxconn",
        "quic-cc-algo",
        "severity-output",
        "tls-ticket-keys",
        "client-sigalgs",
        "proxy-v2-options",
        "send-proxy-v2",
        "default-crt",
        "ca-verify-file",
        "ca-sign-file",
        "ca-sign-pass",
        "crl-file",
        "crt-list",
        "crt-ignore-err",
        "ca-ignore-err",
    }
)

_REDIRECT_WORDS = (
    "code",
    "prefix",
    "drop-query",
    "set-cookie",
    "clear-cookie",
    "location",
    "scheme",
)

_BALANCE_ALGORITHMS = (
    "roundrobin",
    "leastconn",
    "first",
    "source",
    "uri",
    "url_param",
    "random",
    "static-rr",
    "hash",
)

_MODE_VALUES = ("http", "tcp", "health")

_LOG_LEVELS = (
    "emerg",
    "alert",
    "crit",
    "err",
    "warning",
    "notice",
    "info",
    "debug",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
)


def _scope(name: str) -> dict[str, str]:
    return {"name": name}


def _captures(*scopes: str) -> dict[str, dict[str, str]]:
    return {str(i + 1): _scope(s) for i, s in enumerate(scopes)}


def _boundary_alt(words: list[str], limit: int = 5000) -> str:
    if not words:
        return "(?!)never-match"
    return rf"\b{alt_pattern(words, limit=limit)}\b"


def _option_token(opt: str) -> str:
    if opt == "process":
        return "process(?!-)"
    return re.escape(opt)


def _options_with_values(options: list[str]) -> list[str]:
    out: list[str] = []
    for opt in options:
        if opt in _VALUE_OPTION_EXACT or any(h in opt for h in _VALUE_OPTION_HINTS):
            out.append(opt)
    return sorted(out, key=len, reverse=True)


def _statement_rule_keywords(schema: HaproxySchema) -> set[str]:
    return {rule.keyword for rule in schema.statement_rules if is_directive_token(rule.keyword)}


def _group_multword_keywords(schema: HaproxySchema) -> dict[str, list[str]]:
    skip = _statement_rule_keywords(schema)
    groups: dict[str, list[str]] = {}
    for name in schema.keywords:
        if " " not in name:
            continue
        parts = name.split(" ", 1)
        if len(parts) != 2:
            continue
        prefix, suffix = parts
        if prefix in skip or not is_directive_token(prefix):
            continue
        if not is_directive_token(suffix.replace(" ", "-")):
            continue
        groups.setdefault(prefix, []).append(suffix)
    for prefix in groups:
        groups[prefix] = sorted(set(groups[prefix]), key=len, reverse=True)
    return dict(sorted(groups.items()))


def _collect_check_steps(schema: HaproxySchema) -> dict[str, list[str]]:
    steps: dict[str, set[str]] = {"tcp-check": set(), "http-check": set()}
    for name in schema.keywords:
        for prefix in steps:
            if name.startswith(f"{prefix} "):
                step = name[len(prefix) + 1 :]
                if step != "expect" and is_directive_token(step.replace(" ", "-")):
                    steps[prefix].add(step)
    return {k: sorted(v, key=len, reverse=True) for k, v in steps.items()}


def _collect_single_arg_directives(schema: HaproxySchema) -> list[str]:
    skip = _statement_rule_keywords(schema) | action_words(schema)
    words: list[str] = []
    for name, kw in schema.keywords.items():
        if name in skip or " " in name or not is_directive_token(name):
            continue
        model = kw.argument_model
        if model and model.min_args == 1 and (model.max_args == 1 or model.max_args is None):
            words.append(name)
    return sorted(set(words), key=len, reverse=True)


def _collect_enum_words(schema: HaproxySchema) -> list[str]:
    words: set[str] = set(schema.keyword_groups.get("options", []))
    words.update(_MODE_VALUES)
    words.update(_BALANCE_ALGORITHMS)
    words.update(_LOG_LEVELS)
    words.update({"if", "unless", "true", "false", "TRUE", "FALSE"})
    words.update(_REDIRECT_WORDS)
    words.update(_EXPECT_TYPES)
    # Common bind/server flags referenced outside bind lines.
    for opt in schema.keyword_groups.get("bind_options", []):
        if opt in {"ssl", "check", "no-check", "no-backup", "backup", "disabled", "enabled"}:
            words.add(opt)
    for opt in ("accept-proxy", "send-proxy", "send-proxy-v2", "proxy-v2-options", "v4only", "v6only"):
        words.add(opt)
    return sorted(
        (w for w in words if is_directive_token(w) or w in {"if", "unless"}),
        key=len,
        reverse=True,
    )


def _build_sections(schema: HaproxySchema) -> dict[str, Any]:
    sections = sorted(schema.sections.keys())
    sec_alt = alt_pattern(sections)
    proxy_kinds = alt_pattern(["frontend", "backend", "listen"])
    named = alt_pattern(
        [s for s in sections if s not in {"global", "defaults", "frontend", "backend", "listen"}]
    )
    return {
        "patterns": [
            {
                "match": rf"(?m)^(?:\t| )*(defaults)\s+(\S+)(?:\s+(from)\s+(\S+))?",
                "captures": _captures(_SECTION, _PROXY_LABEL, _DIRECTIVE, _PROXY),
            },
            {
                "match": rf"(?m)^(?:\t| )*({proxy_kinds})\s+(\S+)(?:\s+(from)\s+(\S+))?",
                "captures": _captures(_SECTION, _PROXY_LABEL, _DIRECTIVE, _PROXY),
            },
            {
                "match": rf"(?m)^(?:\t| )*({named})\s+(\S+)",
                "captures": _captures(_SECTION, _PROXY_LABEL),
            },
            {
                "name": _SECTION,
                "match": rf"(?m)^(?:\t| )*({sec_alt})\b",
            },
        ]
    }


def _build_directives_with_values(schema: HaproxySchema) -> dict[str, Any]:
    patterns: list[dict[str, Any]] = [
        {
            "match": r"\b(bind)\s+(\S+)(?:\s+(.*))?$",
            "captures": {
                "1": _scope(_DIRECTIVE),
                "2": _scope(_STRING),
                "3": {"patterns": _BIND_TAIL_INCLUDES},
            },
        },
        {
            "match": r"\b(server)\s+(\S+)\s+(\S+)",
            "captures": _captures(_DIRECTIVE, _PROXY, _STRING),
        },
        {
            "match": r"\b(log)\s+(\S+)\s+(\S+)",
            "captures": _captures(_DIRECTIVE, _STRING, _STORAGE),
        },
        {
            "match": r"\b(acl)\s+(\S+)\s+([\w.-]+)",
            "captures": _captures(_DIRECTIVE, _ACL_NAME, _STORAGE),
        },
        {
            "match": r"\b(cookie)\s+(\S+)",
            "captures": _captures(_DIRECTIVE, _PROXY),
        },
        {
            "match": r"\b(lua-load(?:-per-thread|-per-worker)?)\s+(\S+)",
            "captures": _captures(_DIRECTIVE, _STRING),
        },
        {
            "match": r"\b(redirect)\s+(location|prefix|scheme)\s+(\S+)",
            "captures": _captures(_DIRECTIVE, _DIRECTIVE, _STRING),
        },
        {
            "match": r"\b(option)\s+([\w-]+)",
            "captures": _captures(_DIRECTIVE, _STORAGE),
        },
        {
            "match": rf"\b(mode)\s+({alt_pattern(list(_MODE_VALUES))})\b",
            "captures": _captures(_DIRECTIVE, _STORAGE),
        },
        {
            "match": rf"\b(balance)\s+({alt_pattern(list(_BALANCE_ALGORITHMS))})\b",
            "captures": _captures(_DIRECTIVE, _STORAGE),
        },
        {
            "match": r"\b(maxconn)\s+(\S+)",
            "captures": _captures(_DIRECTIVE, _NUMBER),
        },
    ]
    return {"patterns": patterns}


def _build_directives_multiword(schema: HaproxySchema) -> dict[str, Any]:
    patterns: list[dict[str, Any]] = [
        {
            "match": r"\b(no)\s+(option)\b",
            "captures": _captures(_MODIFIER, _DIRECTIVE),
        },
    ]
    for prefix, suffixes in _group_multword_keywords(schema).items():
        if not suffixes:
            continue
        alt = alt_pattern(suffixes, limit=200)
        patterns.append(
            {
                "match": rf"\b({re.escape(prefix)})\s+({alt})\b",
                "captures": _captures(_DIRECTIVE, _DIRECTIVE),
            }
        )
    return {"patterns": patterns}


def _build_rule_actions(schema: HaproxySchema) -> dict[str, Any]:
    patterns: list[dict[str, Any]] = []
    phase_alt = alt_pattern(list(_TCP_PHASES))

    for group_key, rule_kw in (
        ("http_request_actions", "http-request"),
        ("http_response_actions", "http-response"),
        ("http_after_response_actions", "http-after-response"),
    ):
        actions = schema.keyword_groups.get(group_key, [])
        if not actions:
            continue
        act_alt = alt_pattern(actions, limit=500)
        patterns.append(
            {
                "match": rf"\b({re.escape(rule_kw)})\s+({act_alt})\b",
                "captures": _captures(_DIRECTIVE, _DIRECTIVE),
            }
        )

    for group_key, rule_kw in (
        ("tcp_request_actions", "tcp-request"),
        ("tcp_response_actions", "tcp-response"),
    ):
        actions = schema.keyword_groups.get(group_key, [])
        if not actions:
            continue
        act_alt = alt_pattern(actions, limit=200)
        patterns.append(
            {
                "match": rf"\b({re.escape(rule_kw)})\s+({phase_alt})\s+({act_alt})\b",
                "captures": _captures(_DIRECTIVE, _DIRECTIVE, _DIRECTIVE),
            }
        )
        patterns.append(
            {
                "match": rf"\b({re.escape(rule_kw)})\s+({phase_alt})\b",
                "captures": _captures(_DIRECTIVE, _DIRECTIVE),
            }
        )

    header_alt = alt_pattern(list(_HEADER_ACTIONS))
    patterns.append(
        {
            "match": rf"\b({header_alt})\s+(\S+)",
            "captures": _captures(_DIRECTIVE, _STRING),
        }
    )

    standalone_actions = sorted(action_words(schema) - set(_RULE_KEYWORDS), key=len, reverse=True)
    if standalone_actions:
        patterns.append(
            {
                "name": _DIRECTIVE,
                "match": _boundary_alt(standalone_actions, limit=500),
            }
        )

    return {"patterns": patterns}


def _build_check_actions(schema: HaproxySchema) -> dict[str, Any]:
    patterns: list[dict[str, Any]] = []
    steps = _collect_check_steps(schema)
    expect_alt = alt_pattern(list(_EXPECT_TYPES))

    for check_kw, step_list in steps.items():
        if not step_list:
            continue
        step_alt = alt_pattern(step_list, limit=200)
        patterns.append(
            {
                "match": rf"\b({re.escape(check_kw)})\s+({step_alt})\b",
                "captures": _captures(_DIRECTIVE, _DIRECTIVE),
            }
        )

    patterns.append(
        {
            "match": rf"\b(expect)\s+(!)?\s*({expect_alt})\b",
            "captures": _captures(_DIRECTIVE, _MODIFIER, _DIRECTIVE),
        }
    )
    return {"patterns": patterns}


def _build_bind_param_pairs(schema: HaproxySchema) -> dict[str, Any]:
    bind_opts = schema.keyword_groups.get("bind_options", [])
    server_opts = schema.keyword_groups.get("server_options", [])
    all_opts = sorted(set(bind_opts) | set(server_opts), key=len, reverse=True)

    value_opts = _options_with_values(all_opts)
    patterns: list[dict[str, Any]] = []

    if value_opts:
        val_alt = "|".join(_option_token(o) for o in value_opts)
        patterns.append(
            {
                "match": rf"\b({val_alt})\s+(\S+)",
                "captures": _captures(_OPTION, _STRING),
            }
        )

    proxy_flags = [o for o in all_opts if o in {"accept-proxy", "send-proxy", "send-proxy-v2", "proxy-v2-options"}]
    if proxy_flags:
        patterns.append(
            {
                "name": _OPTION,
                "match": rf"(?<=\s)(?:{'|'.join(re.escape(o) for o in proxy_flags)})\b",
            }
        )

    patterns.append(
        {
            "match": r"\b(mode)\s+(\d+)\b",
            "captures": _captures(_OPTION, _NUMBER),
        }
    )
    patterns.append(
        {
            "match": r"\b(level)\s+(admin|user|operator)\b",
            "captures": _captures(_OPTION, _STORAGE),
        }
    )

    flag_opts = [o for o in all_opts if o not in value_opts and o not in proxy_flags]
    if flag_opts:
        flag_alt = "|".join(_option_token(o) for o in flag_opts)
        patterns.append({"name": _OPTION, "match": rf"\b(?:{flag_alt})\b"})

    return {"patterns": patterns}


def _build_log_line() -> dict[str, Any]:
    return {
        "patterns": [
            {
                "match": r"\b(log)\s+(\S+)\s+(\S+)",
                "captures": _captures(_DIRECTIVE, _STRING, _STORAGE),
            },
            {
                "match": r"\b(log-format-sd|log-format)\s+(.+)$",
                "captures": _captures(_DIRECTIVE, _STRING),
            },
        ]
    }


def build_repository(schema: HaproxySchema) -> dict[str, Any]:
    directives = collect_directive_keywords(schema)
    cache_words = collect_cache_keywords(schema)
    single_arg = _collect_single_arg_directives(schema)
    enums = _collect_enum_words(schema)
    fetches = [
        f
        for f in schema.keyword_groups.get("sample_fetches", [])
        if "." in f and is_directive_token(f.split(".")[0])
    ]
    fetch_sample_pat = (
        rf"\b{alt_pattern(fetches, limit=500)}\b"
        if fetches
        else r"\b(?!)never-match"
    )

    single_arg_pat = (
        rf"\b(?:{alt_pattern(single_arg, limit=1000)})\s+(\S+)"
        if single_arg
        else r"(?!)never-match"
    )

    return {
        "comments": {"patterns": [{"name": _COMMENT, "match": "#.*$"}]},
        "preprocessor-directives": {
            "patterns": [
                {
                    "name": _PREPROCESSOR,
                    "match": r"^\s*\.(?:if|elif|else|endif|diag|notice|warning|alert)\b",
                }
            ]
        },
        "strings": {
            "patterns": [
                {
                    "name": "string.quoted.double.haproxy",
                    "begin": '"',
                    "end": '"',
                    "patterns": [{"name": "constant.character.escape.haproxy", "match": r"\\."}],
                },
                {
                    "name": "string.quoted.single.haproxy",
                    "begin": "'",
                    "end": "'",
                    "patterns": [{"name": "constant.character.escape.haproxy", "match": r"\\."}],
                },
            ]
        },
        "sections": _build_sections(schema),
        "cache-keywords": {
            "patterns": [{"name": _DIRECTIVE, "match": _boundary_alt(cache_words, limit=100)}]
        },
        "schema-directives": {
            "patterns": [{"name": _DIRECTIVE, "match": _boundary_alt(directives, limit=5000)}]
        },
        "directives-with-values": _build_directives_with_values(schema),
        "directives-multiword": _build_directives_multiword(schema),
        "rule-actions": _build_rule_actions(schema),
        "check-actions": _build_check_actions(schema),
        "log-line": _build_log_line(),
        "single-arg-directives": {
            "patterns": [
                {
                    "match": single_arg_pat,
                    "captures": {"1": _scope(_DIRECTIVE), "2": _scope(_STRING)},
                }
            ]
        },
        "redirect-keywords": {
            "patterns": [{"name": _DIRECTIVE, "match": _boundary_alt(list(_REDIRECT_WORDS), limit=50)}]
        },
        "bind-param-pairs": _build_bind_param_pairs(schema),
        "addresses": {
            "patterns": [
                {"name": _STRING, "match": r"\*(?::[0-9]+(?:-[0-9]+)?)?"},
                {
                    "name": _STRING,
                    "match": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[+:-]?[0-9]+(?:-[0-9]+)?)?\b",
                },
                {"name": _STRING, "match": r"\b::[\d.a-fA-F:+-]+\b"},
                {"name": _STRING, "match": r"\b[0-9a-fA-F:]*::[\d.a-fA-F:+-]+\b"},
                {"name": _STRING, "match": r":[0-9]+(?:\.[0-9]+)?(?:\.[0-9]+)?(?:\.[0-9]+)?(?:\.[0-9]+)?"},
                {"name": _STRING, "match": r"\b[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+\b"},
                {"name": _STRING, "match": r"/(?:[\w./_$-]|\$\{[^}]+\})*"},
                {"name": _STRING, "match": r"\b(?:localhost|127\.0\.0\.1|::1|0\.0\.0\.0)\b"},
            ]
        },
        "http-methods": {
            "patterns": [
                {
                    "name": _STORAGE,
                    "match": r"\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT|HTTP|TCP)\b",
                }
            ]
        },
        "versions": {
            "patterns": [{"name": _NUMBER, "match": r"\b\d+\.\d+(?:-\d+\.\d+)?\b"}]
        },
        "sample-fetches": {
            "patterns": [
                {"name": _STORAGE, "match": fetch_sample_pat},
                {
                    "name": _STORAGE,
                    "match": r"\b[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]+)+(?:\([^)]*\))?",
                },
            ]
        },
        "numbers": {
            "patterns": [
                {"name": _NUMBER, "match": r"\b[0-9A-Fa-f]*[0-9][0-9A-Fa-f]*\b"},
                {"name": _NUMBER, "match": r"\b[0-9]+(?:\.[0-9]+)?(?:ms|s|m|h|d|k|%)?\b"},
            ]
        },
        "enums": {"patterns": [{"name": _STORAGE, "match": _boundary_alt(enums, limit=2000)}]},
        "modifiers": {
            "patterns": [{"name": _MODIFIER, "match": r"\b(?:no|(?<!from )default|!\s*)\b"}]
        },
        "expressions": {
            "patterns": [
                {"name": _STRING, "match": r"\{[^}]*\}"},
                {"name": _STRING, "match": r"%\[[^\]]*\]"},
                {"name": _STRING, "match": r"\[[^\]]*\]"},
                {"name": "constant.character.escape.haproxy", "match": r'\\[\s"\\]'},
            ]
        },
        "filenames": {
            "patterns": [
                {
                    "name": _STRING,
                    "match": r"\b[\w.-]+\.(?:lua|pem|crt|key|cfg|txt|json|xml|html|so|bin)\b",
                }
            ]
        },
        "punctuation": {
            "patterns": [{"name": _MODIFIER, "match": r"[=,:+\-!|&()\[\]{}^]"}]
        },
        "identifiers": {
            "patterns": [
                {
                    "name": "variable.other.readwrite.haproxy",
                    "match": r"\b[A-Za-z_][\w.-]*\b",
                }
            ]
        },
    }


def build_tm_language(schema: HaproxySchema) -> dict[str, Any]:
    return {
        "$schema": "https://raw.githubusercontent.com/martinring/tmlanguage/master/tmlanguage.json",
        "name": f"HAProxy {schema.version}",
        "scopeName": "source.haproxy",
        "patterns": [
            {"include": "#comments"},
            {"include": "#preprocessor-directives"},
            {"include": "#strings"},
            {"include": "#sections"},
            {"include": "#directives-with-values"},
            {"include": "#directives-multiword"},
            {"include": "#cache-keywords"},
            {"include": "#schema-directives"},
            {"include": "#sample-fetches"},
            {"include": "#rule-actions"},
            {"include": "#check-actions"},
            {"include": "#log-line"},
            {"include": "#bind-param-pairs"},
            {"include": "#single-arg-directives"},
            {"include": "#redirect-keywords"},
            {"include": "#addresses"},
            {"include": "#http-methods"},
            {"include": "#versions"},
            {"include": "#sample-fetches"},
            {"include": "#numbers"},
            {"include": "#enums"},
            {"include": "#modifiers"},
            {"include": "#expressions"},
            {"include": "#filenames"},
            {"include": "#punctuation"},
            {"include": "#identifiers"},
        ],
        "repository": build_repository(schema),
    }
