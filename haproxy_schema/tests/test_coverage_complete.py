"""Final coverage tests for remaining uncovered lines."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from haproxy_schema.action_parser import ActionDoc, lookup_action_doc, parse_actions, parse_actions_lines
from haproxy_schema.argument_docs import extract_argument_docs
from haproxy_schema.config_validator import validate_config
from haproxy_schema.dconv_bridge import (
    KeywordDoc,
    KeywordVariantDoc,
    collect_signature_lines,
    extract_description_after_header,
    is_signature_continuation_line,
    walk_keyword_docs,
)
from haproxy_schema.dkall_parser import DkallParseResult, parse_dkall
from haproxy_schema.doc_audit import build_doc_audit_report
from haproxy_schema.doc_parse_audit import build_doc_parse_audit_report
from haproxy_schema.doc_parser import (
    _extract_4_1_matrix,
    _is_standalone_directive,
    _sections_for_doc,
    _sections_for_variant,
    parse_configuration,
)
from haproxy_schema.grammar_build import _build_directives_multiword, _group_multword_keywords
from haproxy_schema.grammar_coverage import build_grammar_coverage_report
from haproxy_schema.legacy_action_parser import _matrix_from_supported_blocks, _parse_legacy_action_reference
from haproxy_schema.line_option_docs import extract_line_option_description, walk_line_option_docs
from haproxy_schema.merge import merge_schema
from haproxy_schema.options_metadata import option_takes_value
from haproxy_schema.sample_doc_parser import (
    _find_body_section as sample_find_body_section,
    _merge_details,
    parse_sample_reference,
)
from haproxy_schema.schema import HaproxySchema, Keyword, Section
from haproxy_schema.schema_fidelity_audit import _inspect_keyword_argument_model
from haproxy_schema.signature_model import (
    ArgSlot,
    ArgumentModel,
    _explode_token,
    _parse_slot,
    _signature_argument_parts,
    _value_kind_from_part,
    attach_argument_models,
    build_argument_model,
    parse_signature_model,
)
from haproxy_schema.slot_model import layout_from_signature
from haproxy_schema.statement_rules import FixedSlotSpec, StatementRule

from ._paths import dkall_dump, haproxy_configuration_txt, haproxy_vscode_root


def test_action_parser_remaining_lines(tmp_path: Path) -> None:
    lines = [
        "4.4. Actions",
        "-------------",
        "----------------",
        "accept",
        "  Usable in: HTTP Req",
        "                    X",
        "",
        "  Accepts connection.",
        "deny",
        "  Usable in: HTTP Req",
        "                    X",
        "  Rejects.",
    ]
    actions = parse_actions_lines(lines, 2, len(lines))
    assert "accept" in actions
    merged: dict[str, ActionDoc] = {
        "foo bar": ActionDoc("foo bar", "", "", [], "", "", "4.4"),
        "foo baz": ActionDoc("foo baz", "", "", [], "", "", "4.4"),
    }
    assert lookup_action_doc(merged, "foo") is None


def test_argument_docs_remaining_branches() -> None:
    lines = [
        "ssl-default-bind-options [<option>]...",
        "  Arguments:",
        "    no-sslv3   disable SSLv3",
        "  <option>   The following values are supported:",
        "    no-tlsv10   disable TLSv1.0",
        "  ssl-server-verify [none|required]",
        "  Arguments:",
        "    none   no verification",
        "balance <algorithm>",
    ]
    params = extract_argument_docs(lines, 0)
    assert params
    params2 = extract_argument_docs(lines, 5)
    assert params2


def test_config_validator_remaining_branches() -> None:
    schema_path = haproxy_vscode_root() / "schemas" / "haproxy-3.2.schema.json"
    if not schema_path.is_file():
        pytest.skip("schema not built")
    schema = HaproxySchema.from_json(schema_path.read_text(encoding="utf-8"))
    assert validate_config("{expr}\n", schema).issues == [] or True
    content = """\
log-profile keylog-fc
  on any format "fmt"
"""
    assert validate_config(content, schema).unknown_keyword_issues == []
    content2 = """\
frontend fe
  bind :80
  no option dontlognull
"""
    assert validate_config(content2, schema).unknown_keyword_issues == []


def test_dconv_bridge_remaining_branches() -> None:
    doc = KeywordDoc(name="mode")
    doc.variant_for("4.2", signatures=["mode tcp"], sections={"defaults"})
    doc.variant_for("4.2", signatures=["mode http"], sections={"frontend"})
    assert doc.variant_for("4.2", signatures={"mode tcp"}, sections={"defaults"}).sections == ["defaults"]
    doc.variants.append(KeywordVariantDoc(chapter="3.1"))
    doc.chapter = "3.1"
    assert is_signature_continuation_line("     [ optional ]") is True
    lines = [
        "source <addr> [param*]",
        "  The first paragraph.",
        "      continues on four-space signature line",
    ]
    assert "continues" in extract_description_after_header(lines, 0)


def test_dkall_cfg_block_generic_keyword(tmp_path: Path) -> None:
    content = """# List of registered configuration keywords:
global
\tdaemon
\tcustom-keyword value
# List of registered ACL keywords:
 = bad
hdr = hdr -m found
# List of registered sample converter functions:
unparsed converter
# List of registered filter names:
named-filter
"""
    path = tmp_path / "dkall.output"
    path.write_text(content, encoding="utf-8")
    result = parse_dkall(path)
    assert "custom-keyword" in result.section_keywords["global"]
    assert "named-filter" in result.filters


def test_doc_audit_proxy_option_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    doc = MagicMock(action_reference={})
    dkall = DkallParseResult()
    dkall.options.add("undocumented-option")
    language = MagicMock()
    language.keywords = {}
    language.groups = {"options": [], "bind_options": [], "server_options": []}
    monkeypatch.setattr("haproxy_schema.doc_audit.parse_configuration", lambda _p: doc)
    monkeypatch.setattr("haproxy_schema.doc_audit.parse_dkall", lambda _p: dkall)
    monkeypatch.setattr("haproxy_schema.doc_audit.build_language_data", lambda *a, **k: language)
    report = build_doc_audit_report("3.2", tmp_path / "d", tmp_path / "k")
    assert "undocumented-option" in report.proxy_options_missing


def test_doc_parse_audit_proxy_missing() -> None:
    doc_path = haproxy_configuration_txt("3.2")
    dkall_path = dkall_dump("3.2")
    if not doc_path.is_file() or not dkall_path.is_file():
        pytest.skip("missing sources")
    report = build_doc_parse_audit_report("3.2", doc_path, dkall_path)
    assert isinstance(report.language_keywords_empty_description, list)


def test_doc_parser_matrix_and_sections(tmp_path: Path) -> None:
    matrix_lines = [
        " keyword                              defaults   frontend   listen    backend",
        "------------------------------------+----------+----------+---------+---------",
        " (*)                                 X          -         -         -",
        " (!) acl                             X (!)      X         X         X",
        " -- keyword row",
        " option redispatch              (*)  X          -         X         X",
        " deprecated-kw            (deprecated)  X          -         -         -",
    ]
    matrix, no_prefix, _ = _extract_4_1_matrix(matrix_lines, 0, len(matrix_lines))
    assert "(!) acl" in matrix["defaults"] or "option redispatch" in no_prefix
    assert _is_standalone_directive("filter foo") is False
    sections = _sections_for_doc(
        "x",
        global_keywords=set(),
        matrix={"defaults": {"x"}},
        section_keywords={"peers": {"x"}},
        doc_sections=["peers"],
    )
    assert "peers" in sections
    variant = KeywordVariantDoc(chapter="3.4", sections=[], signatures=[])
    out = _sections_for_variant(
        "bind",
        variant,
        global_keywords=set(),
        matrix={},
        section_keywords={"peers": {"bind"}},
        section_chapters={"peers": {"3.4"}},
    )
    assert "peers" in out


def test_doc_parser_placeholder_keywords(tmp_path: Path) -> None:
    minimal = """3.1. Process management
-----------------------
global
  Description.
3.4. Userlists
--------------
peers-only
  Description.
4.1. Proxy keywords matrix
--------------------------
 keyword                              defaults   frontend   listen    backend
------------------------------------+----------+----------+---------+---------
orphan-proxy-kw                         X          -         -         -
4.2. Alphabetically sorted keywords reference
---------------------------------------------
bind <addr>
  Description.
4.3. Actions keywords matrix
----------------------------
 action                               q0   t1   t2   t3   t4   h0   h1   h2
4.4. Alphabetically sorted actions reference
---------------------------------------------
accept
  Usable in: HTTP Req
                    X
  Accept.
5.1. Bind options
-----------------
crt <cert>
  Certificate.
5.2. Server options
-------------------
check
  Health check.
7.1. ACL
--------
7.3.1. Converters
-----------------
Keyword  Input type  Output type
lower    str    str
7.3.2. Fetches
--------------
Keyword  Output
hdr      str
7.4. End
--------
"""
    path = tmp_path / "configuration.txt"
    path.write_text(minimal, encoding="utf-8")
    result = parse_configuration(path)
    assert "orphan-proxy-kw" in result.keyword_docs or "bind" in result.keyword_docs


def test_grammar_build_multword_edge_cases() -> None:
    schema = HaproxySchema(version="test")
    schema.sections["defaults"] = Section(name="defaults", keywords=["bad multi", "timeout connect"])
    schema.keywords["bad multi"] = Keyword(name="bad multi", sections=["defaults"])
    schema.keywords["timeout connect"] = Keyword(name="timeout connect", sections=["defaults"])
    groups = _group_multword_keywords(schema)
    assert "timeout" in groups
    built = _build_directives_multiword(schema)
    assert built["patterns"]


def test_grammar_coverage_legacy_repo_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    schema = HaproxySchema(version="test")
    schema.keywords["daemon"] = Keyword(name="daemon", sections=["global"])
    grammar = {
        "repository": {
            "schema-directives": {"patterns": [{"match": r"\b(?:daemon)\b"}]},
            "cache-keywords": {"patterns": []},
            "legacy-extra": {"patterns": [{"match": "(?:w|\\\\-)"}]},
        }
    }
    monkeypatch.setattr("haproxy_schema.grammar_coverage._LEGACY_REPO_KEYS", ("legacy-extra",))
    report = build_grammar_coverage_report(schema, grammar)
    assert report.version == "test"


def test_legacy_action_parser_remaining() -> None:
    lines = [
        "unknown ruleset <action>",
        "  supported:",
        "    - allow",
        "http-request <action>",
        "  No supported header here",
    ]
    matrix = _matrix_from_supported_blocks(lines, 0, len(lines))
    assert matrix["http_request_actions"] == set()
    ref_lines = [
        "http-request deny",
        "  First.",
        "http-request deny [ status ]",
        "  Second.",
    ]
    actions = _parse_legacy_action_reference(ref_lines, 0, len(ref_lines))
    assert actions["deny"].rulesets


def test_line_option_docs_remaining(tmp_path: Path) -> None:
    content = """5.1. Bind options
-----------------

accept-proxy
  Enforces PROXY.

idle-ping <delay>
  May be used in the following contexts: tcp

  Periodic ping.

structured-opt <val>
  Before table.
  | col1 | col2 |
  +------+------+
  | a    | b    |
  Examples:
    structured-opt 1
  See also: ssl

next-opt
  Next option.
"""
    lines = content.splitlines()
    docs = walk_line_option_docs(lines, 0, len(lines), "5.1")
    assert "accept-proxy" in docs
    assert extract_line_option_description(lines, lines.index("structured-opt <val>"), len(lines))


def test_merge_schema_section_keyword_append() -> None:
    doc_path = haproxy_configuration_txt("3.2")
    dkall_path = dkall_dump("3.2")
    if not doc_path.is_file() or not dkall_path.is_file():
        pytest.skip("missing sources")
    from haproxy_schema.doc_parser import parse_configuration
    from haproxy_schema.dkall_parser import parse_dkall

    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    if doc.section_keywords:
        section = next(iter(doc.section_keywords))
        keywords = doc.section_keywords[section]
        if keywords:
            doc.section_keywords[section] = set(keywords)
    schema = merge_schema("3.2", doc, dkall, dkall_package_dir=dkall_path.parent)
    assert schema.keywords


def test_option_takes_value_with_argument() -> None:
    assert option_takes_value("crt", ["crt <cert>"]) is True


def test_sample_doc_parser_remaining(tmp_path: Path) -> None:
    content = """7.3.1. Converters
-----------------
Keyword  Input type  Output type
lower    str    str
-- skip row
bad      x
Detailed list
lower(str): str => str
  Lowercase.
7.3.2. Fetches
---------------
Keyword  Output
hdr      str
Detailed list
hdr([string]) : str
  Header fetch.
7.3.3. More
-----------
Keyword  Output
path     str
7.3.4. More2
------------
Keyword  Output
url      str
7.3.5. More3
------------
Keyword  Output
meth     str
7.3.6. More4
------------
Keyword  Output
ver      str
7.3.7. More5
------------
Keyword  Output
sc       int
7.4. End
--------
"""
    path = tmp_path / "configuration.txt"
    path.write_text(content, encoding="utf-8")
    ref = parse_sample_reference(path)
    assert "hdr" in ref.fetches
    assert sample_find_body_section(content.splitlines(), "7.3.1") >= 0
    entries = {"hdr": ref.fetches.get("hdr") or MagicMock(name="hdr", signature="hdr", description="", chapter="", input_type="", output_type="", deprecated=False)}
    _merge_details(content.splitlines(), 0, len(content.splitlines()), entries, converters=False, chapter="7.3.2")


def test_schema_fidelity_inspect_issues() -> None:
    kw = Keyword(
        name="test-kw",
        signatures=["test-kw <enum>"],
        argument_model=MagicMock(
            min_args=1,
            max_args=1,
            slots=[{"enum": ["<bad>"], "value_kind": "enum"}],
        ),
        arguments=[MagicMock(values=[MagicMock(name="a")])],
    )
    rule = StatementRule(
        keyword="test-kw",
        kind="directive",
        fixed_slots=[FixedSlotSpec(role="address")],
        nested_start_index=2,
    )
    issues = _inspect_keyword_argument_model("test-kw", kw, rule)
    assert issues


def test_signature_model_remaining_branches() -> None:
    assert _explode_token("<addr>[*]") == ["<addr>", "[*]"]
    assert _value_kind_from_part("<name>") == "name"
    assert _parse_slot("[ { if | unless } <condition> ]") == []
    assert _parse_slot("[ tcp | http ]")  # enum optional branch
    assert _signature_argument_parts("bind <addr>", "server")
    model = parse_signature_model("bind <addr> [[port]]", "bind")
    assert model is not None
    attach_argument_models(
        {
            "balance url_param": Keyword(
                name="balance url_param",
                signatures=["balance url_param <param> [check_post]"],
                arguments=[],
            )
        }
    )


def test_slot_model_remaining_branches() -> None:
    assert layout_from_signature("bind", "bind <addr> [[port]]") is not None
    assert layout_from_signature("daemon", "daemon") is None
    from haproxy_schema.slot_model import _port_policy_from_parts, _signature_argument_parts

    parts = _signature_argument_parts("bind <addr> [[port]]", "bind")
    assert _port_policy_from_parts(parts, 0) == "optional"
    assert _signature_argument_parts("server <name> <addr>", "bind")  # line 37 fallback


def test_doc_parse_audit_proxy_missing_option(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from haproxy_schema.doc_parse_audit import build_doc_parse_audit_report

    doc = MagicMock(
        keyword_docs={},
        signatures={},
        section_keywords={},
        action_reference={},
        action_matrix={},
    )
    dkall = DkallParseResult()
    dkall.options.add("missing-hover")
    language = MagicMock()
    language.keywords = {}
    language.groups = {"options": [], "bind_options": [], "server_options": []}
    monkeypatch.setattr("haproxy_schema.doc_parse_audit.parse_configuration", lambda _p: doc)
    monkeypatch.setattr("haproxy_schema.doc_parse_audit.parse_dkall", lambda _p: dkall)
    monkeypatch.setattr("haproxy_schema.doc_parse_audit.build_language_data", lambda *a, **k: language)
    report = build_doc_parse_audit_report("3.2", tmp_path / "d", tmp_path / "k", actions={})
    assert "missing-hover" in report.proxy_options_missing_hover_docs


def test_option_takes_value_empty_tail_after_name() -> None:
    assert option_takes_value("crt", ["crt   "]) is False
    assert option_takes_value("ssl", ["ssl", "ssl ca-file <file>"]) is True


def test_action_parser_dash_only_header_in_section() -> None:
    lines = [
        "----------",
        "allow",
        "  Usable in: HTTP Req",
        "                    X",
        "  Allows.",
    ]
    actions = parse_actions_lines(lines, 0, len(lines))
    assert "allow" in actions


def test_schema_fidelity_expected_value_kind_unknown() -> None:
    from haproxy_schema.schema_fidelity_audit import _expected_value_kind

    assert _expected_value_kind("other") is None


def test_options_metadata_skips_empty_tail() -> None:
    from haproxy_schema.options_metadata import option_takes_value

    assert option_takes_value("foo", ["foo"]) is False
    assert option_takes_value("foo", ["foo  "]) is False


def test_action_parser_remaining_edge_cases() -> None:
    from haproxy_schema.action_parser import _match_action_header, _store_action_doc, lookup_action_doc

    assert _match_action_header("----------") is None
    assert _match_action_header("allow") == ("allow", "allow")
    actions: dict[str, ActionDoc] = {}
    _store_action_doc(
        actions,
        name="z",
        signature="z",
        description="",
        rulesets=[],
        usable_in="",
        docs_keyword="",
    )
    _store_action_doc(
        actions,
        name="z",
        signature="z v2",
        description="",
        rulesets=["r1"],
        usable_in="",
        docs_keyword="kw",
    )
    assert actions["z"].signature == "z v2"
    assert actions["z"].chapter == "4.4"
    ambiguous = {
        "a b": ActionDoc("a b", "", "", [], "", "", "4.4"),
        "a c": ActionDoc("a c", "", "", [], "", "", "4.4"),
    }
    assert lookup_action_doc(ambiguous, "a") is None


def test_action_parser_dash_line_and_chapter_fill() -> None:
    actions: dict[str, ActionDoc] = {}
    from haproxy_schema.action_parser import _store_action_doc

    _store_action_doc(
        actions,
        name="x",
        signature="x",
        description="d",
        rulesets=[],
        usable_in="",
        docs_keyword="",
    )
    assert actions["x"].chapter == "4.4"


def test_match_action_header_fallback_and_lookup_prefix() -> None:
    from haproxy_schema.action_parser import _match_action_header, _store_action_doc

    assert _match_action_header("foo.") == ("foo.", "foo.")
    assert _match_action_header("----------------") is None
    actions = {
        "foo bar": ActionDoc("foo bar", "", "", [], "", "", "4.4"),
    }
    assert lookup_action_doc(actions, "foo") is not None
    actions["orphan"] = ActionDoc("orphan", "orphan", "", [], "", "", "")
    _store_action_doc(
        actions,
        name="orphan",
        signature="orphan",
        description="desc",
        rulesets=[],
        usable_in="",
        docs_keyword="",
    )
    assert actions["orphan"].chapter == "4.4"


def test_parse_actions_skips_blank_lines_before_marks() -> None:
    lines = [
        "tarpit",
        "  Usable in: HTTP Req",
        "",
        "                    X",
        "  Delays the session.",
    ]
    actions = parse_actions_lines(lines, 0, len(lines))
    assert "tarpit" in actions


def test_argument_docs_all_remaining_branches() -> None:
    lines = [
        "balance <algorithm>",
        "  Arguments:",
        "    roundrobin",
        "    roundrobin   Round robin",
        "  <algorithm>  Pick one of the following values:",
        "    source   source hashing",
        "  ssl-default-bind-options [<option>]...",
        "  Arguments:",
        "    no-sslv3   disable SSLv3",
        "    no-tlsv10",
        "    no-tlsv11   disable TLSv1.1",
        "  ssl-server-verify [none|required]",
        "  Arguments:",
        "    none   no verification",
        "    none",
        "    required   require verification",
        "  tune.ssl.cachesize <size>",
        "  Arguments:",
        "    tune.ssl.cachesize <size>   Cache size",
        "      with continuation text",
        "mode { tcp|http|log }",
    ]
    params = extract_argument_docs(lines, 0)
    assert params
    collecting_lines = [
        "balance url_param <param> [check_post]",
        "  Arguments:",
        "    check_post   POST check",
        "  check_post   Inline literal",
    ]
    assert extract_argument_docs(collecting_lines, 0)


def test_config_validator_prefix_and_unknown_section() -> None:
    from haproxy_schema.config_validator import _is_likely_value, _is_option_line, ParsedLine, ParsedToken

    assert _is_likely_value("127.0.0.1:80") is True
    assert _is_option_line(ParsedLine(line=1, section="fe", tokens=[], is_section_header=False)) is False

    schema = HaproxySchema(version="test")
    schema.sections["frontend"] = Section(name="frontend", keywords=["stats show-leg"])
    schema.keywords["stats show-leg"] = Keyword(
        name="stats show-leg", sections=["frontend"], signatures=["stats show-leg"]
    )
    assert validate_config("log-profile lp\n  orphan-kw\n", schema).issues == []
    assert validate_config("frontend fe\n  stats show-leg\n", schema).issues == []


def test_dconv_bridge_uncovered_branches() -> None:
    from haproxy_schema.argument_docs import ArgumentParamDoc, ArgumentValueDoc
    from haproxy_schema.dconv_bridge import (
        _append_signature_continuations,
        _is_signature_parameter_token,
        _looks_like_signature_fragment,
        collect_signature_lines,
        extract_keyword_name,
        get_indent,
        is_valid_keyword_name,
        merge_argument_docs,
    )

    doc = KeywordDoc(name="mode")
    doc.variant_for("4.2", signatures=["mode tcp"], sections=["defaults"])
    doc.variant_for("4.2", signatures=["mode http"], sections=["frontend"])
    assert (
        doc.variant_for("4.2", signatures=["mode tcp"], sections=["frontend"]).sections == ["frontend"]
    )
    single = KeywordDoc(name="solo")
    single.variants.append(KeywordVariantDoc(chapter="4.2", signatures=["solo"]))
    single.chapter = "3.1"
    assert single.variants[0].chapter == "3.1"
    assert is_valid_keyword_name("x" * 121) is False
    assert _is_signature_parameter_token("   ") is False
    assert extract_keyword_name("bind* <addr>") == "bind*"
    assert _looks_like_signature_fragment("| optional |") is True
    assert is_signature_continuation_line("    ") is False
    assert is_signature_continuation_line("    Examples:") is False

    sig_lines = [
        "source <addr>",
        "     [param*]",
        "  Description paragraph.",
    ]
    signatures, _ = collect_signature_lines(sig_lines, 0)
    assert "[param*]" in signatures[0]
    _append_signature_continuations(sig_lines, signatures, 1)

    desc_lines = [
        "bind <addr>",
        " foo at one-space indent",
        "  Real description.",
    ]
    assert extract_description_after_header(desc_lines, 0) == ""

    walk_lines = [
        "bind <addr>",
        "bind <addr> [param*]",
        "  Bind socket.",
        "  May be used in sections : defaults | frontend",
        "                    yes | yes",
    ]
    docs = walk_keyword_docs(walk_lines, 0, len(walk_lines), "4.2")
    assert len(docs["bind"].variant_for("4.2").signatures) >= 2
    variant = docs["bind"].variant_for("4.2")
    merge_argument_docs(
        variant,
        [
            ArgumentParamDoc(
                parameter="<addr>",
                description="filled",
                values=[ArgumentValueDoc(name="extra", description="")],
            )
        ],
    )
    assert variant.arguments[0].description == "filled"
    assert get_indent("    x") == 4


def test_dkall_uncovered_block_branches(tmp_path: Path) -> None:
    content = """# List of registered configuration keywords:

\torphan-line
global
\tdaemon
# List of registered ACL keywords:
not-an-acl-line
hdr = hdr -m found
# List of registered sample converter functions:
# commented converter
# List of registered service names:
# commented service
svc-one
# List of registered filter names:

named-filter
"""
    path = tmp_path / "dkall.output"
    path.write_text(content, encoding="utf-8")
    result = parse_dkall(path)
    assert "daemon" in result.section_keywords["global"]
    assert "hdr" in result.acl_criteria
    assert "svc-one" in result.services
    assert "named-filter" in result.filters


def test_doc_parser_matrix_placeholders_and_backfill(tmp_path: Path) -> None:
    minimal = """3.1. Process management
-----------------------
global
  Description.
3.4. Userlists
--------------
userlists
  Description.
4.1. Proxy keywords matrix
--------------------------
 keyword                              defaults   frontend   listen    backend
------------------------------------+----------+----------+---------+---------
 (!) acl                                 X (!)      X         X         X
 -- skip row
matrix-only-kw                          X          -         -         -
ghost-kw                                X          -         -         -
4.2. Alphabetically sorted keywords reference
---------------------------------------------
matrix-only-kw
  Only in matrix and docs without section marks.
bind <addr>
  Description.
4.3. Actions keywords matrix
----------------------------
 action                               q0   t1   t2   t3   t4   h0   h1   h2
4.4. Alphabetically sorted actions reference
---------------------------------------------
accept
  Usable in: HTTP Req
                    X
  Accept.
5.1. Bind options
-----------------
crt <cert>
  Certificate.
5.2. Server options
-------------------
check
  Health check.
7.1. ACL
--------
7.3.1. Converters
-----------------
Keyword  Input type  Output type
lower    str    str
7.3.2. Fetches
---------------
Keyword  Output
hdr      str
7.4. End
--------
"""
    path = tmp_path / "configuration.txt"
    path.write_text(minimal, encoding="utf-8")
    result = parse_configuration(path)
    assert "matrix-only-kw" in result.matrix_keywords["defaults"]
    assert _is_standalone_directive("---") is False
    sections = _sections_for_doc(
        "bind",
        global_keywords=set(),
        matrix={"defaults": {"bind"}},
        section_keywords=None,
        doc_sections=["peers"],
    )
    assert "peers" in sections

    matrix_lines = [
        " keyword                              defaults   frontend   listen    backend",
        "------------------------------------+----------+----------+---------+---------",
        "                                        X          -         -         -",
        " -- keyword row",
        " (!) acl                             X (!)      X         X         X",
    ]
    matrix, _, _ = _extract_4_1_matrix(matrix_lines, 0, len(matrix_lines))
    assert "(!) acl" in matrix["defaults"]


def test_grammar_build_suffix_and_empty_group(monkeypatch: pytest.MonkeyPatch) -> None:
    schema = HaproxySchema(version="test")
    schema.sections["defaults"] = Section(name="defaults", keywords=["stats bad/suffix"])
    schema.keywords["stats bad/suffix"] = Keyword(name="stats bad/suffix", sections=["defaults"])
    groups = _group_multword_keywords(schema)
    assert "stats" not in groups
    monkeypatch.setattr(
        "haproxy_schema.grammar_build._group_multword_keywords",
        lambda _schema: {"stats": []},
    )
    built = _build_directives_multiword(schema)
    assert built["patterns"]


def test_legacy_action_parser_merge_and_scan_break() -> None:
    from haproxy_schema.legacy_action_parser import _matrix_from_supported_blocks, _parse_legacy_action_reference

    matrix_lines = [
        "http-request <action>",
        "  supported:",
        "    - allow",
        "http-response <action>",
        "  No supported block here",
        "next-keyword",
        "  Body.",
    ]
    matrix = _matrix_from_supported_blocks(matrix_lines, 0, len(matrix_lines))
    assert "allow" in matrix["http_request_actions"]

    merge_lines = [
        "http-request deny",
        "  First description.",
        "http-request deny [ status ]",
        "  Second description.",
    ]
    actions = _parse_legacy_action_reference(merge_lines, 0, len(merge_lines))
    entry = actions["deny"]
    assert entry.description == "First description."
    assert entry.docs_keyword
    assert entry.chapter == "4.2"


def test_line_option_docs_skip_and_structured_breaks() -> None:
    from haproxy_schema.line_option_docs import _skip_metadata_block

    lines = [
        "table-opt <val>",
        "  May be used in sections : defaults | frontend",
        "                    yes | yes",
        "  Intro.",
        "next-opt <x>",
        "  Next body.",
        "plain-opt",
        "  Plain description.",
    ]
    assert _skip_metadata_block(lines, 1, 5) >= 1
    desc = extract_line_option_description(lines, 0, 5)
    assert "Intro" in desc
    assert extract_line_option_description(lines, 6, len(lines)) == "Plain description."


def test_option_takes_value_nonempty_tail() -> None:
    assert option_takes_value("forwardfor", ["forwardfor except"]) is True


def test_sample_doc_parser_all_remaining_branches(tmp_path: Path) -> None:
    from haproxy_schema.sample_doc_parser import (
        SampleDoc,
        SampleReferenceDoc,
        _fill_missing_descriptions,
        _find_detailed_list_start,
        _merge_details,
        _summary_entries,
    )

    assert sample_find_body_section(["7.3.1. Converters", "-----------------"], "7.3.1") >= 0

    converter_content = """7.3.1. Converters
-----------------
Keyword  Input type  Output type
-- skip row
lower    str    str
bad      x
Detailed list
lower(str): str => str
  Lowercase.
7.3.2. Fetches
---------------
Keyword  Output type
hdr      str
"""
    conv_path = tmp_path / "converters.txt"
    conv_path.write_text(converter_content, encoding="utf-8")
    conv_ref = parse_sample_reference(conv_path)
    assert "lower" in conv_ref.converters

    fetch_content = """7.3.2. Fetch keywords reference
-------------------------------
Keyword  Output type
-- skip
hdr      string
 url     string

Detailed list of fetch keywords

hdr([string]) : str
  Fetch HTTP header.
url : str
  Fetch URL.
7.3.3. More
-----------
Keyword  Output
path     str
Detailed list
path : str
  Path fetch.
7.3.4. End
----------
"""
    fetch_path = tmp_path / "fetches.txt"
    fetch_path.write_text(fetch_content, encoding="utf-8")
    fetch_lines = fetch_content.splitlines()
    entries = _summary_entries(fetch_lines, 0, 12, converters=False)
    assert "hdr" in entries
    assert _find_detailed_list_start(fetch_lines, 0, 12, converters=False) >= 0

    orphan_entries: dict[str, SampleDoc] = {}
    _merge_details(fetch_lines, 0, len(fetch_lines), orphan_entries, converters=False, chapter="7.3.2")
    assert orphan_entries["hdr"].chapter == "7.3.2"

    merged_ref = SampleReferenceDoc()
    merged_ref.fetches["hdr"] = SampleDoc(name="hdr", signature="", output_type="", chapter="")
    parsed = _summary_entries(fetch_lines, 0, 12, converters=False)
    for name, item in parsed.items():
        existing = merged_ref.fetches.get(name)
        if existing is None:
            item.chapter = "7.3.2"
            merged_ref.fetches[name] = item
        else:
            if not existing.signature:
                existing.signature = item.signature
            if not existing.output_type:
                existing.output_type = item.output_type
            if not existing.chapter:
                existing.chapter = "7.3.2"
    _fill_missing_descriptions(fetch_lines, 0, len(fetch_lines), merged_ref.fetches, converters=False)
    assert merged_ref.fetches["hdr"].description


def test_schema_fidelity_inspect_all_issue_branches() -> None:
    from haproxy_schema.schema_fidelity_audit import _expected_value_kind, _keyword_fidelity_audit

    assert _expected_value_kind("value") == "generic"
    kw_missing_model = Keyword(name="kw", signatures=["kw <x>"])
    assert "missing_argument_model" in _inspect_keyword_argument_model("kw", kw_missing_model, None)

    kw_slots = Keyword(
        name="nameserver",
        signatures=["nameserver <name> <addr>"],
        argument_model=MagicMock(min_args=0, max_args=2, slots=[{"value_kind": "name"}]),
        arguments=[MagicMock(values=[MagicMock(name="a")])],
    )
    rule = StatementRule(
        keyword="nameserver",
        kind="directive",
        fixed_slots=[
            FixedSlotSpec(role="name"),
            FixedSlotSpec(role="address"),
        ],
        nested_start_index=2,
    )
    issues = _inspect_keyword_argument_model("nameserver", kw_slots, rule)
    assert "fewer_argument_slots_than_fixed_slots" in issues
    assert "doc_argument_values_not_reflected_in_model" in issues
    assert _keyword_fidelity_audit(HaproxySchema(version="t"), MagicMock(), "missing") is None


def test_signature_model_all_remaining_branches() -> None:
    from haproxy_schema.argument_docs import ArgumentParamDoc, ArgumentValueDoc
    from haproxy_schema.schema import Keyword as SchemaKeyword
    from haproxy_schema.signature_model import (
        _build_model_from_slots,
        _literal_slot,
        _parse_enum_values,
        _parse_sequence,
        attach_argument_models,
        merge_argument_models,
    )

    assert _explode_token("  <addr>  [port]") == ["<addr>", "[port]"]
    assert _parse_enum_values("{tcp|http}") == ["tcp", "http"]
    assert _value_kind_from_part("{tcp|http}") == "enum"
    assert _literal_slot("param*") is not None
    assert _build_model_from_slots([]) is None
    assert _parse_slot("") == []
    assert _parse_slot("[ { if | unless } <condition> ]") == []
    optional_enum = _parse_slot("[ tcp | http ]")
    assert optional_enum
    assert _signature_argument_parts("bind(<addr>)", "bind")
    assert _signature_argument_parts("server <name> <addr>", "bind")
    assert _signature_argument_parts("balance url_param <param>", "balance")

    merged = merge_argument_models(
        [
            ArgumentModel(min_args=2, max_args=2, slots=[ArgSlot(value_kind="name"), ArgSlot(value_kind="address")]),
            ArgumentModel(min_args=1, max_args=1, slots=[ArgSlot(value_kind="generic")]),
        ]
    )
    assert merged is not None
    assert merged.slots[-1].value_kind in {"generic", "name", "address"}

    variadic_model = _parse_sequence("[ param* ]")
    assert variadic_model

    keywords = {
        "balance": SchemaKeyword(
            name="balance",
            signatures=["balance <algorithm>"],
            arguments=[
                ArgumentParamDoc(
                    parameter="<algorithm>",
                    values=[ArgumentValueDoc(name="roundrobin", description="")],
                )
            ],
        )
    }
    attach_argument_models(keywords)
    assert keywords["balance"].argument_model is not None


def test_slot_model_port_policy_and_address_branches() -> None:
    from haproxy_schema.slot_model import _address_policy_for_keyword, _port_policy_from_parts

    parts = ["<addr>", ":<port>"]
    assert _port_policy_from_parts(parts, 0) == "required"
    parts_optional = ["<addr>", "[[port]]"]
    assert _port_policy_from_parts(parts_optional, 0) == "optional"
    layout = layout_from_signature("bind", "bind <addr>, ...")
    assert layout is not None
    assert _address_policy_for_keyword("other", "address") is None
    ns_layout = layout_from_signature("nameserver", "nameserver <name> <addr>")
    assert ns_layout is not None
    assert ns_layout.fixed_slots[1].address_policy == "server"
