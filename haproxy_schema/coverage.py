from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .dkall_parser import DkallParseResult
from .doc_parser import DocParseResult
from .schema import HaproxySchema


@dataclass
class CoverageReport:
    version: str
    doc_only_keywords: list[str] = field(default_factory=list)
    dkall_only_keywords: list[str] = field(default_factory=list)
    keywords_without_argument_model: list[str] = field(default_factory=list)
    sections_doc_only: list[str] = field(default_factory=list)
    sections_dkall_only: list[str] = field(default_factory=list)
    sample_fetches_count: int = 0
    sample_converters_count: int = 0
    statement_rules_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_coverage_report(
    version: str,
    doc: DocParseResult,
    dkall: DkallParseResult,
    schema: HaproxySchema,
) -> CoverageReport:
    doc_keywords: set[str] = set(doc.global_keywords)
    for keywords in doc.matrix_keywords.values():
        doc_keywords.update(keywords)
    for keywords in doc.section_keywords.values():
        doc_keywords.update(keywords)
    for keywords in doc.action_matrix.values():
        doc_keywords.update(keywords)
    doc_keywords.update(doc.signatures.keys())

    dkall_keywords: set[str] = set()
    for keywords in dkall.section_keywords.values():
        dkall_keywords.update(keywords)

    schema_keywords = set(schema.keywords.keys())

    doc_only = sorted(doc_keywords - dkall_keywords - schema_keywords)
    dkall_only = sorted(dkall_keywords - doc_keywords)

    without_model = sorted(
        name
        for name, kw in schema.keywords.items()
        if kw.signatures and kw.argument_model is None
    )

    doc_sections = set(doc.matrix_keywords.keys()) | {"global"} | set(doc.section_keywords.keys())
    dkall_sections = set(dkall.section_keywords.keys())

    return CoverageReport(
        version=version,
        doc_only_keywords=doc_only,
        dkall_only_keywords=dkall_only,
        keywords_without_argument_model=without_model,
        sections_doc_only=sorted(doc_sections - dkall_sections),
        sections_dkall_only=sorted(dkall_sections - doc_sections),
        sample_fetches_count=len(dkall.sample_fetches_structured),
        sample_converters_count=len(dkall.sample_converters_structured),
        statement_rules_count=len(schema.statement_rules),
    )
