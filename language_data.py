from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote
import json

from .action_parser import ActionDoc, parse_actions
from .dkall_parser import DkallParseResult, parse_dkall
from .doc_parser import DocParseResult, SECTIONS_MATRIX, parse_configuration


@dataclass
class GroupItem:
    name: str
    description: str = ""
    signature: str = ""
    rulesets: list[str] = field(default_factory=list)


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
class LanguageKeyword:
    name: str
    sections: list[str]
    signatures: list[str]
    description: str
    docsUrl: str
    arguments: list[LanguageArgumentParam] = field(default_factory=list)


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


def docs_url(version: str, keyword: str, chapter: str = "") -> str:
    base = f"https://docs.haproxy.org/{version}/configuration.html"
    anchor = quote(f"{chapter}-{keyword}" if chapter else keyword, safe="")
    return f"{base}#{anchor}"


def build_language_data(
    version: str,
    doc: DocParseResult,
    dkall: DkallParseResult,
    actions: dict[str, ActionDoc],
) -> HaproxyLanguageData:
    docs_base = f"https://docs.haproxy.org/{version}/configuration.html"
    data = HaproxyLanguageData(version=version, docsBaseUrl=docs_base)

    for name, kdoc in sorted(doc.keyword_docs.items()):
        sections = list(kdoc.sections)
        signatures = kdoc.signatures or [name]
        chapter = kdoc.chapter or ("4.2" if any(name in doc.matrix_keywords.get(s, set()) for s in SECTIONS_MATRIX) else "3.1")
        data.keywords[name] = LanguageKeyword(
            name=name,
            sections=sections,
            signatures=signatures,
            description=kdoc.description,
            docsUrl=docs_url(version, name, chapter),
            arguments=[
                LanguageArgumentParam(
                    parameter=param.parameter,
                    description=param.description,
                    values=[
                        LanguageArgumentValue(name=value.name, description=value.description)
                        for value in param.values
                    ],
                )
                for param in kdoc.arguments
            ],
        )

    def group_items(names: list[str], descriptions: dict[str, str], signatures: dict[str, str]) -> list[GroupItem]:
        items: list[GroupItem] = []
        for name in names:
            action = actions.get(name)
            items.append(
                GroupItem(
                    name=name,
                    description=descriptions.get(name, action.description if action else ""),
                    signature=signatures.get(name, action.signature if action else ""),
                    rulesets=list(action.rulesets) if action else [],
                )
            )
        return items

    action_desc = {name: a.description for name, a in actions.items()}
    action_sigs = {name: a.signature for name, a in actions.items()}

    data.groups = {
        "options": group_items(sorted(set(dkall.options) | _collect_doc_options(doc)), {}, {}),
        "bind_options": group_items(sorted(dkall.bind_options), {}, {}),
        "server_options": group_items(sorted(dkall.server_options), {}, {}),
        "http_request_actions": group_items(
            sorted(dkall.http_request_actions), action_desc, action_sigs
        ),
        "http_response_actions": group_items(
            sorted(dkall.http_response_actions), action_desc, action_sigs
        ),
        "http_after_response_actions": group_items(
            sorted(dkall.http_after_response_actions), action_desc, action_sigs
        ),
        "services": group_items(sorted(dkall.services), {}, {}),
        "tcp_request_actions": group_items(
            sorted(set(dkall.tcp_request_actions) | {"accept", "reject", "inspect-delay", "expect-proxy"}),
            action_desc,
            action_sigs,
        ),
        "tcp_response_actions": group_items(
            sorted(set(dkall.tcp_response_actions) | {"accept", "reject"}),
            action_desc,
            action_sigs,
        ),
        "acl_criteria": group_items(sorted(dkall.acl_criteria), {}, {}),
        "sample_fetches": group_items(sorted(dkall.sample_fetches), {}, {}),
        "sample_converters": group_items(sorted(dkall.sample_converters), {}, {}),
        "filters": group_items(sorted(dkall.filters), {}, {}),
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
    actions = parse_actions(doc_path)
    return build_language_data(version, doc, dkall, actions)
