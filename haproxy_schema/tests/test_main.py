from __future__ import annotations

import json
from pathlib import Path

import pytest

from haproxy_schema.__main__ import main, make_parser

from ._paths import dkall_dump, haproxy_configuration_txt, haproxy_vscode_root


def test_make_parser_requires_subcommand() -> None:
    with pytest.raises(SystemExit):
        make_parser().parse_args([])


def test_main_build_minimal(tmp_path: Path) -> None:
    doc_path = haproxy_configuration_txt("3.2")
    dkall_path = dkall_dump("3.2")
    if not doc_path.is_file() or not dkall_path.is_file():
        pytest.skip("missing HAProxy sources")

    out = tmp_path / "schema.json"
    code = main(
        [
            "build",
            "--doc",
            str(doc_path),
            "--dkall",
            str(dkall_path),
            "--out",
            str(out),
            "--version",
            "3.2",
        ]
    )
    assert code == 0
    assert out.is_file()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["version"] == "3.2"


def test_main_build_with_all_outputs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    doc_path = haproxy_configuration_txt("3.2")
    dkall_path = dkall_dump("3.2")
    if not doc_path.is_file() or not dkall_path.is_file():
        pytest.skip("missing HAProxy sources")

    schema_out = tmp_path / "schema.json"
    lang_out = tmp_path / "lang.json"
    grammar_out = tmp_path / "grammar.json"
    coverage_out = tmp_path / "coverage.json"

    code = main(
        [
            "build",
            "--doc",
            str(doc_path),
            "--dkall",
            str(dkall_path),
            "--out",
            str(schema_out),
            "--language-data-out",
            str(lang_out),
            "--grammar-out",
            str(grammar_out),
            "--coverage-out",
            str(coverage_out),
            "--version",
            "3.2",
        ]
    )
    assert code == 0
    assert schema_out.is_file()
    assert lang_out.is_file()
    assert grammar_out.is_file()
    assert coverage_out.is_file()
    assert "Coverage:" in capsys.readouterr().out


def test_main_emit_grammar(tmp_path: Path) -> None:
    schema_path = haproxy_vscode_root() / "schemas" / "haproxy-3.2.schema.json"
    if not schema_path.is_file():
        pytest.skip("schema not built")

    grammar_out = tmp_path / "haproxy.tmLanguage.json"
    code = main(["emit-grammar", "--schema", str(schema_path), "--out", str(grammar_out)])
    assert code == 0
    assert grammar_out.is_file()


def test_main_check_grammar_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    schema_path = haproxy_vscode_root() / "schemas" / "haproxy-3.2.schema.json"
    if not schema_path.is_file():
        pytest.skip("schema not built")

    report_out = tmp_path / "report.json"
    code = main(
        [
            "check-grammar",
            "--schema",
            str(schema_path),
            "--report-out",
            str(report_out),
        ]
    )
    assert code == 0
    assert report_out.is_file()
    assert "Grammar OK:" in capsys.readouterr().out


def test_main_check_grammar_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(
        json.dumps(
            {
                "version": "test",
                "sections": {"global": {"name": "global", "keywords": ["daemon"]}},
                "keywords": {"daemon": {"name": "daemon", "sections": ["global"]}},
                "tokens": {},
            }
        ),
        encoding="utf-8",
    )
    grammar_path = tmp_path / "grammar.json"
    grammar_path.write_text(
        json.dumps(
            {
                "repository": {
                    "schema-directives": {"patterns": [{"match": r"\b(?:nothing)\b"}]},
                    "cache-keywords": {"patterns": []},
                }
            }
        ),
        encoding="utf-8",
    )
    code = main(["check-grammar", "--schema", str(schema_path), "--grammar", str(grammar_path)])
    assert code == 1
    out = capsys.readouterr().out
    assert "missing directive in grammar: daemon" in out


def test_main_check_grammar_invalid_json_falls_back(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    schema_path = haproxy_vscode_root() / "schemas" / "haproxy-3.2.schema.json"
    if not schema_path.is_file():
        pytest.skip("schema not built")

    bad_grammar = tmp_path / "bad.json"
    bad_grammar.write_text("{not valid json", encoding="utf-8")
    code = main(["check-grammar", "--schema", str(schema_path), "--grammar", str(bad_grammar)])
    assert code == 0
    assert "Grammar OK:" in capsys.readouterr().out


def test_main_audit_docs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    doc_path = haproxy_configuration_txt("3.2")
    dkall_path = dkall_dump("3.2")
    if not doc_path.is_file() or not dkall_path.is_file():
        pytest.skip("missing HAProxy sources")

    out = tmp_path / "audit.json"
    code = main(
        [
            "audit-docs",
            "--doc",
            str(doc_path),
            "--dkall",
            str(dkall_path),
            "--version",
            "3.2",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    assert out.is_file()
    captured = capsys.readouterr().out
    assert "Proxy options missing hover docs:" in captured
    assert "Bind options missing hover docs:" in captured
    assert "Server options missing hover docs:" in captured


def test_main_doc_parse_audit(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    doc_path = haproxy_configuration_txt("3.2")
    dkall_path = dkall_dump("3.2")
    if not doc_path.is_file() or not dkall_path.is_file():
        pytest.skip("missing HAProxy sources")

    out = tmp_path / "parse-audit.json"
    code = main(
        [
            "doc-parse-audit",
            "--doc",
            str(doc_path),
            "--dkall",
            str(dkall_path),
            "--version",
            "3.2",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    assert out.is_file()
    captured = capsys.readouterr().out
    assert "Doc parse audit:" in captured
    assert "Language payload:" in captured
    assert "Actions:" in captured


def test_main_schema_fidelity_audit(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    doc_path = haproxy_configuration_txt("3.2")
    dkall_path = dkall_dump("3.2")
    if not doc_path.is_file() or not dkall_path.is_file():
        pytest.skip("missing HAProxy sources")

    out = tmp_path / "fidelity.json"
    code = main(
        [
            "schema-fidelity-audit",
            "--doc",
            str(doc_path),
            "--dkall",
            str(dkall_path),
            "--version",
            "3.2",
            "--out",
            str(out),
        ]
    )
    assert code == 0
    assert out.is_file()
    captured = capsys.readouterr().out
    assert "Schema fidelity:" in captured
    assert "Sample functions:" in captured
