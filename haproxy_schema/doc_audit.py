"""Report keywords and line options missing hover documentation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .dkall_parser import parse_dkall
from .doc_parser import parse_configuration
from .language_data import build_language_data


@dataclass
class DocAuditReport:
    version: str
    proxy_options_missing: list[str] = field(default_factory=list)
    bind_options_missing: list[str] = field(default_factory=list)
    server_options_missing: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "proxy_options_missing": self.proxy_options_missing,
            "bind_options_missing": self.bind_options_missing,
            "server_options_missing": self.server_options_missing,
        }


def build_doc_audit_report(version: str, doc_path: Path, dkall_path: Path) -> DocAuditReport:
    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    language = build_language_data(version, doc, dkall, doc.action_reference)

    proxy_missing: list[str] = []
    for opt in sorted(set(dkall.options)):
        kw = language.keywords.get(f"option {opt}")
        group = next((g for g in language.groups["options"] if g.name == opt), None)
        if not (kw and kw.description) and not (group and group.description):
            proxy_missing.append(opt)

    bind_missing = [
        item.name
        for item in language.groups["bind_options"]
        if not item.description
    ]
    server_missing = [
        item.name
        for item in language.groups["server_options"]
        if not item.description
    ]

    return DocAuditReport(
        version=version,
        proxy_options_missing=proxy_missing,
        bind_options_missing=bind_missing,
        server_options_missing=server_missing,
    )
