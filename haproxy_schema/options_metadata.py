"""Identify proxy/server options that take a value argument (from option name shape)."""

from __future__ import annotations

VALUE_OPTION_HINTS = (
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

VALUE_OPTION_EXACT = frozenset(
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


def option_takes_value(option: str) -> bool:
    lower = option.lower()
    if lower in VALUE_OPTION_EXACT:
        return True
    return any(hint in lower for hint in VALUE_OPTION_HINTS)


def collect_options_with_value(options: list[str]) -> list[str]:
    return sorted({opt for opt in options if option_takes_value(opt)})
