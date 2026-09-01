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


def test_main_check_grammar_invalid_json_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    schema_path = haproxy_vscode_root() / "schemas" / "haproxy-3.2.schema.json"
    if not schema_path.is_file():
        pytest.skip("schema not built")

    bad_grammar = tmp_path / "bad.json"
    bad_grammar.write_text("{not valid json", encoding="utf-8")
    code = main(["check-grammar", "--schema", str(schema_path), "--grammar", str(bad_grammar)])
    assert code == 1
    assert "invalid grammar:" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("option", "community_name", "kind"),
    [
        ("--out", "haproxy-3.2.schema.json", "schema"),
        ("--language-data-out", "haproxy-3.2.language.json", "language data"),
        ("--grammar-out", "haproxy-3.2.tmLanguage.json", "grammar"),
        ("--grammar-out", "HAPROXY-3.2.TMLANGUAGE.JSON", "grammar"),
        ("--grammar-out", "haproxy.tmLanguage.json", "grammar"),
    ],
)
def test_main_build_hapee_refuses_community_artifact_targets(
    tmp_path: Path, option: str, community_name: str, kind: str
) -> None:
    arguments = [
        "build-hapee",
        "--hapee-version",
        "3.2r1",
        "--dkall",
        "unused-dkall.txt",
        "--out",
        str(tmp_path / "haproxy-3.2r1.schema.json"),
    ]
    if option == "--out":
        arguments[-1] = str(tmp_path / community_name)
    else:
        arguments.extend([option, str(tmp_path / community_name)])

    with pytest.raises(SystemExit, match=f"Refusing to overwrite Community {kind}"):
        main(arguments)


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


def test_make_parser_build_hapee() -> None:
    args = make_parser().parse_args(
        [
            "build-hapee",
            "--hapee-version",
            "3.2r1",
            "--dkall",
            "dkall.txt",
            "--out",
            "haproxy-3.2r1.schema.json",
            "--language-data-out",
            "haproxy-3.2r1.language.json",
        ]
    )
    assert args.hapee_version == "3.2r1"
    assert args.out == "haproxy-3.2r1.schema.json"
    assert args.language_data_out == "haproxy-3.2r1.language.json"


def test_make_parser_build_hapee_requires_out() -> None:
    with pytest.raises(SystemExit):
        make_parser().parse_args(["build-hapee", "--hapee-version", "3.2r1", "--dkall", "dkall.txt"])


def test_main_build_hapee_writes_schema(tmp_path: Path) -> None:
    html = Path(__file__).parent / "fixtures" / "hapee-mini.html"
    dkall_path = dkall_dump("3.2")
    assert html.is_file()
    assert dkall_path.is_file()

    schema_out = tmp_path / "haproxy-3.2r1.schema.json"
    language_out = tmp_path / "haproxy-3.2r1.language.json"
    code = main(
        [
            "build-hapee",
            "--hapee-version",
            "3.2r1",
            "--html",
            str(html),
            "--allow-unpinned-html",
            "--dkall",
            str(dkall_path),
            "--out",
            str(schema_out),
            "--language-data-out",
            str(language_out),
        ]
    )
    assert code == 0
    assert schema_out.is_file()
    assert language_out.is_file()
    data = json.loads(schema_out.read_text(encoding="utf-8"))
    language = json.loads(language_out.read_text(encoding="utf-8"))
    assert data["version"] == "3.2r1"
    assert "module-load" in data["keywords"]
    assert "module-path" in data["keywords"]
    assert language["version"] == "3.2r1"
    assert "module-load" in language["keywords"]
    converters = data.get("sample_converters") or {}
    if "has_ctl" in converters:
        assert "has_ctl" in (data.get("keyword_groups") or {}).get("sample_converters", [])
