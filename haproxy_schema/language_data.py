from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote
import json

from .action_parser import ActionDoc, lookup_action_doc, parse_actions
from .dkall_parser import DkallParseResult, parse_dkall
from .dkall_supplement import supplement_missing_tls_options
from .doc_parser import DocParseResult, SECTIONS_MATRIX, parse_configuration
from .merge import build_action_groups


@dataclass
class GroupItem:
    name: str
    description: str = ""
    signature: str = ""
    rulesets: list[str] = field(default_factory=list)
    docsUrl: str = ""


@dataclass
class LanguageArgumentValue:
    name: str
    description: str = ""


@dataclass
class LanguageArgumentParam:
    parameter: str
    description: str = ""
    values: list[LanguageArgumentValue] = field(default_factory=list)


@dataclass
class LanguageKeywordVariant:
    chapter: str
    sections: list[str]
    signatures: list[str]
    description: str
    docsUrl: str
    arguments: list[LanguageArgumentParam] = field(default_factory=list)
    contexts: list[str] = field(default_factory=list)


@dataclass
class LanguageKeyword:
    name: str
    sections: list[str]
    signatures: list[str]
    description: str
    docsUrl: str
    arguments: list[LanguageArgumentParam] = field(default_factory=list)
    variants: list[LanguageKeywordVariant] = field(default_factory=list)


@dataclass
class HaproxyLanguageData:
    version: str
    docsBaseUrl: str
    keywords: dict[str, LanguageKeyword] = field(default_factory=dict)
    groups: dict[str, list[GroupItem]] = field(default_factory=dict)

    def to_json_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_json_dict(), indent=indent, sort_keys=True)

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json() + "\n", encoding="utf-8")


def docs_anchor(keyword: str, chapter: str = "") -> str:
    """Build a documentation fragment id matching haproxy-dconv anchor rules.

    Configuration keywords use ``{chapter}-{keyword}`` (KeyWordParser href).
    Sample fetches/converters and non-conflicting cross-links use the bare
    ``keyword`` when no chapter is set.
    """
    anchor = f"{chapter}-{keyword}" if chapter else keyword
    return quote(anchor, safe="")


def docs_url(version: str, keyword: str, chapter: str = "") -> str:
    base = f"https://docs.haproxy.org/{version}/configuration.html"
    return f"{base}#{docs_anchor(keyword, chapter)}"


def action_docs_url(version: str, action: ActionDoc | None, default_name: str, default_chapter: str = "") -> str:
    if action is None:
        if not default_chapter:
            return ""
        return docs_url(version, default_name, default_chapter)
    keyword = action.docs_keyword or action.name or default_name
    chapter = action.chapter or default_chapter
    if not keyword or not chapter:
        return ""
    return docs_url(version, keyword, chapter)


def _acl_group_items(mapping: dict[str, str], signature_fmt: str = "") -> list[GroupItem]:
    return [
        GroupItem(
            name=name,
            description=desc,
            signature=signature_fmt.format(name=name) if signature_fmt else name,
        )
        for name, desc in sorted(mapping.items())
    ]


def _sample_signature(item: object) -> str:
    signature = getattr(item, "signature", "") or ""
    if getattr(item, "deprecated", False) and signature and "(deprecated)" not in signature.lower():
        return f"{signature} (deprecated)"
    return signature


def build_language_data(
    version: str,
    doc: DocParseResult,
    dkall: DkallParseResult,
    actions: dict[str, ActionDoc],
) -> HaproxyLanguageData:
    docs_base = f"https://docs.haproxy.org/{version}/configuration.html"
    data = HaproxyLanguageData(version=version, docsBaseUrl=docs_base)

    def language_arguments(arguments: list[Any]) -> list[LanguageArgumentParam]:
        return [
            LanguageArgumentParam(
                parameter=param.parameter,
                description=param.description,
                values=[
                    LanguageArgumentValue(name=value.name, description=value.description)
                    for value in param.values
                ],
            )
            for param in arguments
        ]

    for name, kdoc in sorted(doc.keyword_docs.items()):
        sections = list(kdoc.sections)
        signatures = kdoc.signatures or [name]
        chapter = kdoc.chapter or (
            "4.2" if any(name in doc.matrix_keywords.get(s, set()) for s in SECTIONS_MATRIX) else "3.1"
        )
        variants = [
            LanguageKeywordVariant(
                chapter=variant.chapter,
                sections=list(variant.sections),
                signatures=list(variant.signatures) or [name],
                description=variant.description,
                docsUrl=docs_url(version, name, variant.chapter),
                arguments=language_arguments(variant.arguments),
                contexts=list(variant.contexts),
            )
            for variant in kdoc.variants
        ]
        data.keywords[name] = LanguageKeyword(
            name=name,
            sections=sections,
            signatures=signatures,
            description=kdoc.description,
            docsUrl=docs_url(version, name, chapter),
            arguments=language_arguments(kdoc.arguments),
            variants=variants,
        )

    def group_items(
        names: list[str],
        descriptions: dict[str, str],
        signatures: dict[str, str],
        *,
        docs_chapter: str | None = None,
    ) -> list[GroupItem]:
        items: list[GroupItem] = []
        for name in names:
            action = lookup_action_doc(actions, name)
            doc_url = docs_url(version, name, docs_chapter or "") if docs_chapter is not None else ""
            items.append(
                GroupItem(
                    name=name,
                    description=descriptions.get(name, action.description if action else ""),
                    signature=signatures.get(name, action.signature if action else ""),
                    rulesets=list(action.rulesets) if action else [],
                    docsUrl=doc_url,
                )
            )
        return items

    def action_group_items(names: list[str]) -> list[GroupItem]:
        items: list[GroupItem] = []
        for name in names:
            action = lookup_action_doc(actions, name)
            items.append(
                GroupItem(
                    name=name,
                    description=action.description if action else "",
                    signature=action.signature if action else "",
                    rulesets=list(action.rulesets) if action else [],
                    docsUrl=action_docs_url(version, action, name, "4.4"),
                )
            )
        return items

    action_groups = build_action_groups(doc, dkall)

    option_desc = {
        name: doc.description for name, doc in doc.bind_option_docs.items() if doc.description
    }
    option_sigs = {
        name: doc.signatures[0]
        for name, doc in doc.bind_option_docs.items()
        if doc.signatures
    }
    server_desc = {
        name: doc.description for name, doc in doc.server_option_docs.items() if doc.description
    }
    server_sigs = {
        name: doc.signatures[0]
        for name, doc in doc.server_option_docs.items()
        if doc.signatures
    }

    data.groups = {
        "options": group_items(sorted(set(dkall.options) | _collect_doc_options(doc)), {}, {}),
        "bind_options": group_items(
            sorted(dkall.bind_options),
            option_desc,
            option_sigs,
            docs_chapter="5.1",
        ),
        "server_options": group_items(
            sorted(dkall.server_options),
            server_desc,
            server_sigs,
            docs_chapter="5.2",
        ),
        "http_request_actions": action_group_items(action_groups["http_request_actions"]),
        "http_response_actions": action_group_items(action_groups["http_response_actions"]),
        "http_after_response_actions": action_group_items(action_groups["http_after_response_actions"]),
        "services": group_items(sorted(dkall.services), {}, {}),
        "tcp_request_actions": action_group_items(action_groups["tcp_request_actions"]),
        "tcp_response_actions": action_group_items(action_groups["tcp_response_actions"]),
        "quic_initial_actions": action_group_items(action_groups["quic_initial_actions"]),
        "acl_criteria": group_items(sorted(dkall.acl_criteria), {}, {}),
        "sample_fetches": group_items(
            sorted(dkall.sample_fetches),
            {name: item.description for name, item in doc.sample_reference.fetches.items() if item.description},
            {name: _sample_signature(item) for name, item in doc.sample_reference.fetches.items() if item.signature},
            docs_chapter="",
        ),
        "sample_converters": group_items(
            sorted(dkall.sample_converters),
            {name: item.description for name, item in doc.sample_reference.converters.items() if item.description},
            {name: _sample_signature(item) for name, item in doc.sample_reference.converters.items() if item.signature},
            docs_chapter="",
        ),
        "filters": group_items(sorted(dkall.filters), {}, {}),
        "acl_flags": _acl_group_items(doc.acl_reference.flags),
        "acl_match_methods": _acl_group_items(doc.acl_reference.match_methods, '-m {name}'),
        "acl_int_operators": _acl_group_items(doc.acl_reference.int_operators),
        "acl_string_match_methods": _acl_group_items(
            doc.acl_reference.string_match_methods, "-m {name}"
        ),
        "acl_predefined": _acl_group_items(doc.acl_reference.predefined_acls),
    }

    return data


def _collect_doc_options(doc: DocParseResult) -> set[str]:
    options: set[str] = set()
    for keywords in doc.matrix_keywords.values():
        for keyword in keywords:
            if keyword.startswith("option "):
                options.add(keyword[len("option ") :])
    for keyword in doc.signatures:
        if keyword.startswith("option "):
            options.add(keyword[len("option ") :])
    return options


def build_from_paths(
    doc_path: Path,
    dkall_path: Path,
    version: str,
) -> HaproxyLanguageData:
    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    supplement_missing_tls_options(dkall, dkall_path.parent)
    actions = parse_actions(doc_path)
    return build_language_data(version, doc, dkall, actions)
