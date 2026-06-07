from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .action_parser import ActionDoc, parse_actions
from .dkall_parser import parse_dkall
from .doc_parser import DocParseResult, parse_configuration
from .language_data import build_language_data


def _has_description(text: str) -> bool:
    return bool(text and text.strip())


def _collect_action_group_names(doc: DocParseResult) -> set[str]:
    names: set[str] = set()
    for keywords in doc.action_matrix.values():
        names.update(keywords)
    return names


@dataclass
class DocParseAuditReport:
    version: str
    keyword_docs_count: int = 0
    signature_keywords_count: int = 0
    signatures_total_count: int = 0
    section_keywords_count: int = 0
    action_reference_count: int = 0
    language_keywords_count: int = 0
    keywords_missing_description: list[str] = field(default_factory=list)
    keywords_missing_signatures: list[str] = field(default_factory=list)
    signature_keywords_missing_keyword_doc: list[str] = field(default_factory=list)
    keyword_docs_missing_language_payload: list[str] = field(default_factory=list)
    language_keywords_missing_doc_source: list[str] = field(default_factory=list)
    language_keywords_empty_description: list[str] = field(default_factory=list)
    actions_missing_description: list[str] = field(default_factory=list)
    actions_without_rulesets: list[str] = field(default_factory=list)
    action_reference_only: list[str] = field(default_factory=list)
    action_matrix_only: list[str] = field(default_factory=list)
    proxy_options_missing_hover_docs: list[str] = field(default_factory=list)
    bind_options_missing_hover_docs: list[str] = field(default_factory=list)
    server_options_missing_hover_docs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "keyword_docs_count": self.keyword_docs_count,
            "signature_keywords_count": self.signature_keywords_count,
            "signatures_total_count": self.signatures_total_count,
            "section_keywords_count": self.section_keywords_count,
            "action_reference_count": self.action_reference_count,
            "language_keywords_count": self.language_keywords_count,
            "keywords_missing_description": self.keywords_missing_description,
            "keywords_missing_signatures": self.keywords_missing_signatures,
            "signature_keywords_missing_keyword_doc": self.signature_keywords_missing_keyword_doc,
            "keyword_docs_missing_language_payload": self.keyword_docs_missing_language_payload,
            "language_keywords_missing_doc_source": self.language_keywords_missing_doc_source,
            "language_keywords_empty_description": self.language_keywords_empty_description,
            "actions_missing_description": self.actions_missing_description,
            "actions_without_rulesets": self.actions_without_rulesets,
            "action_reference_only": self.action_reference_only,
            "action_matrix_only": self.action_matrix_only,
            "proxy_options_missing_hover_docs": self.proxy_options_missing_hover_docs,
            "bind_options_missing_hover_docs": self.bind_options_missing_hover_docs,
            "server_options_missing_hover_docs": self.server_options_missing_hover_docs,
        }


def build_doc_parse_audit_report(
    version: str,
    doc_path: Path,
    dkall_path: Path,
    *,
    actions: dict[str, ActionDoc] | None = None,
) -> DocParseAuditReport:
    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    action_docs = actions if actions is not None else (doc.action_reference or parse_actions(doc_path))
    language = build_language_data(version, doc, dkall, action_docs)

    keyword_doc_names = set(doc.keyword_docs.keys())
    signature_keyword_names = set(doc.signatures.keys())
    language_keyword_names = set(language.keywords.keys())
    action_matrix_names = _collect_action_group_names(doc)
    action_reference_names = set(action_docs.keys())

    proxy_missing: list[str] = []
    for opt in sorted(set(dkall.options)):
        kw = language.keywords.get(f"option {opt}")
        group = next((g for g in language.groups["options"] if g.name == opt), None)
        if not (_has_description(kw.description) if kw else False) and not (
            _has_description(group.description) if group else False
        ):
            proxy_missing.append(opt)

    bind_missing = [
        item.name
        for item in language.groups["bind_options"]
        if not _has_description(item.description)
    ]
    server_missing = [
        item.name
        for item in language.groups["server_options"]
        if not _has_description(item.description)
    ]

    return DocParseAuditReport(
        version=version,
        keyword_docs_count=len(keyword_doc_names),
        signature_keywords_count=len(signature_keyword_names),
        signatures_total_count=sum(len(signatures) for signatures in doc.signatures.values()),
        section_keywords_count=len(doc.section_keywords),
        action_reference_count=len(action_reference_names),
        language_keywords_count=len(language_keyword_names),
        keywords_missing_description=sorted(
            name for name, item in doc.keyword_docs.items() if not _has_description(item.description)
        ),
        keywords_missing_signatures=sorted(
            name for name, item in doc.keyword_docs.items() if not item.signatures
        ),
        signature_keywords_missing_keyword_doc=sorted(signature_keyword_names - keyword_doc_names),
        keyword_docs_missing_language_payload=sorted(keyword_doc_names - language_keyword_names),
        language_keywords_missing_doc_source=sorted(language_keyword_names - keyword_doc_names),
        language_keywords_empty_description=sorted(
            name for name, item in language.keywords.items() if not _has_description(item.description)
        ),
        actions_missing_description=sorted(
            name for name, item in action_docs.items() if not _has_description(item.description)
        ),
        actions_without_rulesets=sorted(
            name for name, item in action_docs.items() if not item.rulesets
        ),
        action_reference_only=sorted(action_reference_names - action_matrix_names),
        action_matrix_only=sorted(action_matrix_names - action_reference_names),
        proxy_options_missing_hover_docs=proxy_missing,
        bind_options_missing_hover_docs=bind_missing,
        server_options_missing_hover_docs=server_missing,
    )
