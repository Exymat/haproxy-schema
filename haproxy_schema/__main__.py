from __future__ import annotations

import argparse
import json
from pathlib import Path

from .action_parser import parse_actions
from .coverage import build_coverage_report
from .dkall_parser import parse_dkall
from .doc_parser import parse_configuration
from .grammar_coverage import report_from_paths
from .grammar_emitter import write_tm_language
from .language_data import build_language_data
from .merge import merge_schema
from .schema import HaproxySchema


def _check_grammar_cmd(args: argparse.Namespace) -> int:
    schema_path = Path(args.schema)
    grammar_path = Path(args.grammar) if args.grammar else None
    template = Path(args.grammar_template) if args.grammar_template else None
    report = report_from_paths(schema_path, grammar_path or schema_path, template_path=template)
    if args.report_out:
        Path(args.report_out).write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
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
    template = Path(args.grammar_template) if args.grammar_template else grammar_path.parent / "haproxy.tmLanguage.json"
    write_tm_language(schema, grammar_path, template_path=template)
    return 0


def _build_cmd(args: argparse.Namespace) -> int:
    doc_path = Path(args.doc)
    doc = parse_configuration(doc_path)
    dkall_path = Path(args.dkall)
    dkall = parse_dkall(dkall_path)
    dkall_dir = dkall_path.parent
    schema = merge_schema(args.version, doc, dkall, dkall_package_dir=dkall_dir)
    schema.write(Path(args.out))

    if args.language_data_out:
        actions = doc.action_reference or parse_actions(doc_path)
        language = build_language_data(args.version, doc, dkall, actions)
        language.write(Path(args.language_data_out))

    if args.grammar_out:
        grammar_path = Path(args.grammar_out)
        template = Path(args.grammar_template) if args.grammar_template else grammar_path.parent / "haproxy.tmLanguage.json"
        write_tm_language(schema, grammar_path, template_path=template)

    if args.coverage_out:
        report = build_coverage_report(args.version, doc, dkall, schema)
        Path(args.coverage_out).write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
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
        help="Base TextMate grammar to patch (default: haproxy.tmLanguage.json beside output)",
    )
    build.add_argument(
        "--coverage-out",
        default="",
        help="Output coverage report JSON path",
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
        help="Base TextMate grammar to patch (default: haproxy.tmLanguage.json beside output)",
    )
    emit.set_defaults(func=_emit_grammar_cmd)

    check = sub.add_parser("check-grammar", help="Verify emitted TextMate grammar matches schema directives")
    check.add_argument("--schema", required=True, help="Path to haproxy-X.Y.schema.json")
    check.add_argument(
        "--grammar",
        default="",
        help="Existing grammar JSON (optional; default: emit from template + schema)",
    )
    check.add_argument(
        "--grammar-template",
        default="",
        help="Base TextMate grammar template (required when --grammar omitted)",
    )
    check.add_argument("--report-out", default="", help="Write JSON report path")
    check.set_defaults(func=_check_grammar_cmd)
    return parser


def main() -> int:
    parser = make_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
