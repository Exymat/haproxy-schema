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
from .hapee_versions import (
    default_hapee_html_fixture,
    default_oss_configuration_txt,
    hapee_release,
    infer_monorepo_root,
    verify_hapee_source,
    verify_hapee_source_text,
)
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
    try:
        report = report_from_paths(
            schema_path,
            grammar_path or schema_path,
            strict_grammar=grammar_path is not None,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"invalid grammar: {error}")
        return 1
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


def _resolve_hapee_html(args: argparse.Namespace, release) -> Path:
    from .html_doc_parser import load_hapee_html

    html_path = Path(args.html) if args.html else None
    if args.fetch:
        html = load_hapee_html(url=release.doc_url)
        if not args.allow_unpinned_html:
            try:
                html = verify_hapee_source_text(html, release)
            except ValueError as error:
                raise SystemExit(str(error)) from error
        fixture_path = default_hapee_html_fixture(release.version)
        fixture_path.parent.mkdir(parents=True, exist_ok=True)
        write_text_lf(fixture_path, html)
        html_path = fixture_path
    if html_path is None:
        html_path = default_hapee_html_fixture(release.version)
    if not html_path.is_file():
        raise SystemExit(f"HAPEE HTML not found: {html_path}")
    if not args.allow_unpinned_html:
        try:
            verify_hapee_source(html_path, release)
        except ValueError as error:
            raise SystemExit(str(error)) from error
    return html_path


def _reject_hapee_community_output(path: Path | None, release, kind: str) -> None:
    if path is None:
        return
    community_names = {
        "schema": {f"haproxy-{release.oss_base}.schema.json"},
        "language data": {f"haproxy-{release.oss_base}.language.json"},
        "grammar": {
            "haproxy.tmLanguage.json",
            f"haproxy-{release.oss_base}.tmLanguage.json",
        },
    }
    if path.name.casefold() in {name.casefold() for name in community_names[kind]}:
        expected_suffix = {
            "schema": "schema.json",
            "language data": "language.json",
            "grammar": "tmLanguage.json",
        }[kind]
        raise SystemExit(
            f"Refusing to overwrite Community {kind} with HAPEE {release.version}: {path}. "
            f"Use haproxy-{release.version}.{expected_suffix}."
        )


def _build_hapee_cmd(args: argparse.Namespace) -> int:
    from .enterprise_overlays import apply_enterprise_module_overlays
    from .html_doc_parser import load_hapee_html, parse_configuration_html

    release = hapee_release(args.hapee_version)
    schema_out = Path(args.out)
    language_out = Path(args.language_data_out) if args.language_data_out else None
    grammar_out = Path(args.grammar_out) if args.grammar_out else None
    _reject_hapee_community_output(schema_out, release, "schema")
    _reject_hapee_community_output(language_out, release, "language data")
    _reject_hapee_community_output(grammar_out, release, "grammar")

    html_path = _resolve_hapee_html(args, release)
    monorepo = infer_monorepo_root()
    oss_doc = Path(args.oss_doc) if args.oss_doc else default_oss_configuration_txt(
        release.oss_base,
        monorepo_root=monorepo,
    )
    if not oss_doc.is_file():
        raise SystemExit(f"OSS configuration.txt not found for base {release.oss_base}: {oss_doc}")

    html = load_hapee_html(path=html_path)
    doc = parse_configuration_html(html, release=release, oss_reference_doc=oss_doc)

    dkall_path = Path(args.dkall)
    dkall = parse_dkall(dkall_path)
    apply_enterprise_module_overlays(release.version, doc, dkall)
    schema = merge_schema(
        release.oss_base,
        doc,
        dkall,
        dkall_package_dir=dkall_path.parent,
        haproxy_root=monorepo / f"haproxy_git/haproxy-{release.oss_base}" if monorepo is not None else None,
        edition="hapee",
    )
    schema.version = release.version
    schema.write(schema_out)
    print(f"HAPEE schema: {len(schema.keywords)} keywords -> {schema_out}")

    actions = doc.action_reference or parse_actions(oss_doc)
    language = build_language_data(
        release.version,
        doc,
        dkall,
        actions,
        docs_base=release.doc_url,
    )
    if language_out is not None:
        language.write(language_out)
        print(f"HAPEE language data: {len(language.keywords)} keywords -> {language_out}")

    if grammar_out is not None:
        write_tm_language(schema, grammar_out)
        print(f"HAPEE grammar -> {grammar_out}")

    if args.coverage_out:
        report = build_coverage_report(release.version, doc, dkall, schema, edition="hapee")
        write_text_lf(Path(args.coverage_out), json.dumps(report.to_dict(), indent=2) + "\n")
        print(
            f"Coverage: {len(report.doc_only_keywords)} doc-only keywords, "
            f"{len(report.dkall_only_keywords)} dkall-only, "
            f"{len(report.hapee_doc_only_keywords)} hapee-doc-only, "
            f"{len(report.keywords_without_argument_model)} without argument_model"
        )
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

    build_hapee = sub.add_parser(
        "build-hapee",
        help="Build full HAPEE schema and language-data JSON from official HTML documentation",
    )
    build_hapee.add_argument("--hapee-version", required=True, help="HAPEE release (e.g. 3.2r1)")
    build_hapee.add_argument("--html", default="", help="Path to cached HAPEE configuration manual HTML")
    build_hapee.add_argument(
        "--fetch",
        action="store_true",
        help="Download HTML from haproxy.com (not stored in git; used to regenerate artifacts)",
    )
    build_hapee.add_argument(
        "--allow-unpinned-html",
        action="store_true",
        help="Allow a custom HTML fixture whose checksum is not the release pin (tests/development only)",
    )
    build_hapee.add_argument(
        "--oss-doc",
        default="",
        help="OSS configuration.txt for ACL/sample/logformat reference chapters",
    )
    build_hapee.add_argument("--dkall", required=True, help="Path to OSS dkall dump for the matching base version")
    build_hapee.add_argument("--out", required=True, help="Output HAPEE schema path (haproxy-X.Yr1.schema.json)")
    build_hapee.add_argument(
        "--language-data-out",
        default="",
        help="Output HAPEE language-data JSON path (haproxy-X.Yr1.language.json)",
    )
    build_hapee.add_argument(
        "--grammar-out",
        default="",
        help="Optional TextMate grammar JSON path (haproxy-X.Yr1.tmLanguage.json; do not overwrite community grammars)",
    )
    build_hapee.add_argument("--coverage-out", default="", help="Output coverage report JSON path")
    build_hapee.set_defaults(func=_build_hapee_cmd)

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
