from __future__ import annotations

import argparse
import json
from pathlib import Path

from .action_parser import parse_actions
from .coverage import build_coverage_report
from .dkall_parser import parse_dkall
from .doc_parse_audit import build_doc_parse_audit_report
from .doc_parser import parse_configuration
from .grammar_coverage import report_from_paths
from .grammar_emitter import write_tm_language
from .io_util import write_text_lf
from .language_data import build_language_data
from .doc_audit import build_doc_audit_report
from .merge import merge_schema
from .schema_fidelity_audit import build_schema_fidelity_report
from .schema import HaproxySchema


def _audit_docs_cmd(args: argparse.Namespace) -> int:
    report = build_doc_audit_report(args.version, Path(args.doc), Path(args.dkall))
    if args.out:
        write_text_lf(Path(args.out), json.dumps(report.to_dict(), indent=2) + "\n")
    print(f"Proxy options missing hover docs: {len(report.proxy_options_missing)}")
    if report.proxy_options_missing:
        print("  " + ", ".join(report.proxy_options_missing))
    print(f"Bind options missing hover docs: {len(report.bind_options_missing)}")
    if report.bind_options_missing:
        print("  " + ", ".join(report.bind_options_missing))
    print(f"Server options missing hover docs: {len(report.server_options_missing)}")
    if report.server_options_missing:
        print("  " + ", ".join(report.server_options_missing))
    return 0


def _doc_parse_audit_cmd(args: argparse.Namespace) -> int:
    report = build_doc_parse_audit_report(args.version, Path(args.doc), Path(args.dkall))
    if args.out:
        write_text_lf(Path(args.out), json.dumps(report.to_dict(), indent=2) + "\n")
    print(
        f"Doc parse audit: {report.keyword_docs_count} keyword docs, "
        f"{report.signature_keywords_count} signature keywords, "
        f"{len(report.keywords_missing_description)} missing descriptions"
    )
    print(
        f"Language payload: {report.language_keywords_count} keywords, "
        f"{len(report.language_keywords_empty_description)} empty descriptions"
    )
    print(
        f"Actions: {report.action_reference_count} reference entries, "
        f"{len(report.actions_without_rulesets)} without rulesets"
    )
    return 0


def _schema_fidelity_audit_cmd(args: argparse.Namespace) -> int:
    report = build_schema_fidelity_report(args.version, Path(args.doc), Path(args.dkall))
    if args.out:
        write_text_lf(Path(args.out), json.dumps(report.to_dict(), indent=2) + "\n")
    print(
        f"Schema fidelity: {report.keywords_with_argument_model_count}/"
        f"{report.keywords_with_signatures_count} keywords with argument_model, "
        f"{len(report.keyword_argument_issues)} keywords with model issues"
    )
    print(
        f"Sample functions: {report.sample_fetches.structured_count}/{report.sample_fetches.total_count} fetches, "
        f"{report.sample_converters.structured_count}/{report.sample_converters.total_count} converters structured"
    )
    print(
        f"Consumer fallback gaps: {len(report.consumer_fallback_required)} total "
        f"({len(report.line_option_semantic_gaps)} line-option, "
        f"{len(report.statement_rule_semantic_gaps)} statement-rule, "
        f"{len(report.reference_pattern_gaps)} reference-pattern)"
    )
    return 0


def _check_grammar_cmd(args: argparse.Namespace) -> int:
    schema_path = Path(args.schema)
    grammar_path = Path(args.grammar) if args.grammar else None
    report = report_from_paths(schema_path, grammar_path or schema_path)
    if args.report_out:
        write_text_lf(Path(args.report_out), json.dumps(report.to_dict(), indent=2) + "\n")
    if not report.ok:
        for word in report.missing_in_grammar[:20]:
            print(f"missing directive in grammar: {word}")
        for word in report.missing_cache_in_grammar:
            print(f"missing cache keyword in grammar: {word}")
        for short, long in report.prefix_conflicts_in_grammar[:10]:
            print(f"prefix conflict: {short} vs {long}")
        for word in report.legacy_hyphen_when_schema_underscore[:20]:
            print(f"legacy hyphen stale (schema uses underscore): {word}")
        return 1
    print(
        f"Grammar OK: {report.grammar_schema_directive_count} directives, "
        f"{report.grammar_cache_keyword_count} cache keywords"
    )
    return 0


def _emit_grammar_cmd(args: argparse.Namespace) -> int:
    schema_path = Path(args.schema)
    schema = HaproxySchema.from_json_dict(json.loads(schema_path.read_text(encoding="utf-8")))
    grammar_path = Path(args.out)
    write_tm_language(schema, grammar_path)
    return 0


def _build_cmd(args: argparse.Namespace) -> int:
    doc_path = Path(args.doc)
    doc = parse_configuration(doc_path)
    dkall_path = Path(args.dkall)
    dkall = parse_dkall(dkall_path)
    dkall_dir = dkall_path.parent
    schema = merge_schema(
        args.version,
        doc,
        dkall,
        dkall_package_dir=dkall_dir,
        haproxy_root=doc_path.parent.parent if doc_path.name == "configuration.txt" else None,
    )
    schema.write(Path(args.out))
    if args.metadata_provenance_out:
        report = getattr(schema, "_metadata_provenance_report", None)
        if report is not None:
            write_text_lf(
                Path(args.metadata_provenance_out),
                json.dumps(report, indent=2, sort_keys=True) + "\n",
            )

    if args.language_data_out:
        actions = doc.action_reference or parse_actions(doc_path)
        language = build_language_data(args.version, doc, dkall, actions)
        language.write(Path(args.language_data_out))

    if args.grammar_out:
        grammar_path = Path(args.grammar_out)
        write_tm_language(schema, grammar_path)

    if args.coverage_out:
        report = build_coverage_report(args.version, doc, dkall, schema)
        write_text_lf(Path(args.coverage_out), json.dumps(report.to_dict(), indent=2) + "\n")
        print(
            f"Coverage: {len(report.doc_only_keywords)} doc-only keywords, "
            f"{len(report.dkall_only_keywords)} dkall-only, "
            f"{len(report.keywords_without_argument_model)} without argument_model"
        )
    return 0


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build HAProxy schema and IDE language data")
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="Build schema and optional language-data JSON")
    build.add_argument("--doc", required=True, help="Path to configuration.txt")
    build.add_argument("--dkall", required=True, help="Path to dkall.output")
    build.add_argument("--out", required=True, help="Output schema path")
    build.add_argument(
        "--language-data-out",
        default="",
        help="Output IDE language-data JSON path (completion/hover)",
    )
    build.add_argument(
        "--grammar-out",
        default="",
        help="Output TextMate grammar JSON path",
    )
    build.add_argument(
        "--grammar-template",
        default="",
        help="Deprecated and ignored; grammar emission is fully generated from schema data",
    )
    build.add_argument(
        "--coverage-out",
        default="",
        help="Output coverage report JSON path",
    )
    build.add_argument(
        "--metadata-provenance-out",
        default="",
        help="Output internal schema metadata provenance audit JSON path",
    )
    build.add_argument("--version", default="3.2", help="HAProxy version string")
    build.add_argument(
        "--dconv-path",
        default="",
        help="Path to haproxy-dconv repo (reserved; rules are vendored in dconv_bridge)",
    )
    build.set_defaults(func=_build_cmd)

    emit = sub.add_parser("emit-grammar", help="Regenerate TextMate grammar from an existing schema JSON")
    emit.add_argument("--schema", required=True, help="Path to haproxy-X.Y.schema.json")
    emit.add_argument("--out", required=True, help="Output grammar path")
    emit.add_argument(
        "--grammar-template",
        default="",
        help="Deprecated and ignored; grammar emission is fully generated from schema data",
    )
    emit.set_defaults(func=_emit_grammar_cmd)

    check = sub.add_parser("check-grammar", help="Verify emitted TextMate grammar matches schema directives")
    check.add_argument("--schema", required=True, help="Path to haproxy-X.Y.schema.json")
    check.add_argument(
        "--grammar",
        default="",
        help="Existing grammar JSON (optional; default: emit directly from schema)",
    )
    check.add_argument(
        "--grammar-template",
        default="",
        help="Deprecated and ignored; grammar emission is fully generated from schema data",
    )
    check.add_argument("--report-out", default="", help="Write JSON report path")
    check.set_defaults(func=_check_grammar_cmd)

    audit = sub.add_parser("audit-docs", help="List proxy/bind/server options missing hover documentation")
    audit.add_argument("--doc", required=True, help="Path to configuration.txt")
    audit.add_argument("--dkall", required=True, help="Path to dkall.output")
    audit.add_argument("--version", default="3.4", help="HAProxy version string")
    audit.add_argument("--out", default="", help="Optional JSON report path")
    audit.set_defaults(func=_audit_docs_cmd)

    parse_audit = sub.add_parser(
        "doc-parse-audit",
        help="Audit configuration.txt extraction quality for schema/hover/action payloads",
    )
    parse_audit.add_argument("--doc", required=True, help="Path to configuration.txt")
    parse_audit.add_argument("--dkall", required=True, help="Path to dkall.output")
    parse_audit.add_argument("--version", default="3.4", help="HAProxy version string")
    parse_audit.add_argument("--out", default="", help="Optional JSON report path")
    parse_audit.set_defaults(func=_doc_parse_audit_cmd)

    fidelity = sub.add_parser(
        "schema-fidelity-audit",
        help="Audit how completely token arguments/options are modeled in the generated schema",
    )
    fidelity.add_argument("--doc", required=True, help="Path to configuration.txt")
    fidelity.add_argument("--dkall", required=True, help="Path to dkall.output")
    fidelity.add_argument("--version", default="3.4", help="HAProxy version string")
    fidelity.add_argument("--out", default="", help="Optional JSON report path")
    fidelity.set_defaults(func=_schema_fidelity_audit_cmd)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
