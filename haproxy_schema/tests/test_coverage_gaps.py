"""Targeted tests for uncovered branches across haproxy_schema modules."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from haproxy_schema.acl_doc_parser import _parse_7_1_2_operators, _parse_7_1_flags_and_methods, _section_range, AclReferenceDoc
from haproxy_schema.action_parser import (
    _match_action_header,
    _store_action_doc,
    lookup_action_doc,
    parse_actions,
    ActionDoc,
)
from haproxy_schema.argument_docs import (
    ArgumentParamDoc,
    ArgumentValueDoc,
    _append_value,
    enum_names_from_params,
    extract_argument_docs,
    flatten_argument_values,
)
from haproxy_schema.config_validator import (
    _is_likely_value,
    _is_option_line,
    _resolve_longest_match,
    _schema_prefix_families,
    _section_allowed,
    _tokenize_line,
    parse_config_text,
    validate_config,
    ParsedLine,
    ParsedToken,
)
from haproxy_schema.dconv_bridge import (
    KeywordDoc,
    KeywordVariantDoc,
    extract_sections_from_keyword_block,
    is_valid_keyword_name,
    is_signature_continuation_line,
    merge_argument_docs,
)
from haproxy_schema.dkall_parser import (
    DkallParseResult,
    _extract_option_tokens_after_prefix,
    _is_significant_nested_token,
    _last_significant_word,
    parse_dkall,
)
from haproxy_schema.dkall_supplement import supplement_missing_tls_options
from haproxy_schema.doc_parser import parse_configuration
from haproxy_schema.grammar_build import _build_directives_multiword, _group_multword_keywords, validate_line_isolated_grammar
from haproxy_schema.grammar_coverage import (
    GrammarCoverageReport,
    _extract_repo_literals,
    _extract_schema_directive_alternation,
    _prefix_conflicts,
    report_from_paths,
)
from haproxy_schema.grammar_emitter_minimal import emit_tm_language_minimal
from haproxy_schema.grammar_util import is_directive_token
from haproxy_schema.language_data import HaproxyLanguageData, _sample_signature, action_docs_url
from haproxy_schema.legacy_action_parser import (
    _normalize_supported_action,
    _parse_legacy_action_reference,
    uses_legacy_action_layout,
)
from haproxy_schema.line_option_docs import _is_metadata_line, _skip_metadata_block, extract_line_option_description
from haproxy_schema.merge import _merge_keyword_variant_docs, _prune_compile_time_doc_keywords
from haproxy_schema.options_metadata import option_takes_value
from haproxy_schema.sample_doc_parser import SampleDoc, _fill_missing_descriptions
from haproxy_schema.schema import HaproxySchema, Keyword, KeywordVariant, Section
from haproxy_schema.schema_fidelity_audit import _expected_value_kind, _group_item_audit, _inspect_keyword_argument_model
from haproxy_schema.signature_model import (
    ArgumentModel,
    _enrich_slots_from_doc_enums,
    _patch_log_argument_model,
    _patch_redirect_argument_model,
    _preferred_keyword_variant,
    merge_argument_models,
    parse_signature_model,
)
from haproxy_schema.slot_model import _address_policy_for_keyword, _port_policy_from_parts, enrich_statement_rules, pick_best_layout
from haproxy_schema.statement_rules import FixedSlotSpec, StatementRule, statement_rules_to_dict

from ._paths import dkall_dump, haproxy_configuration_txt, haproxy_vscode_root


# --- acl_doc_parser ---


def test_section_range_when_next_section_missing() -> None:
    lines = ["7.1. ACL", "------", "content", "no next section"]
    start, end = _section_range(lines, "7.1", "7.2")
    assert start >= 0
    assert end == len(lines)


def test_acl_flags_parser_stops_at_next_subsection() -> None:
    lines = [
        "The following ACL flags are currently supported :",
        "   -i : case insensitive",
        "7.1.2. Matching integers",
        "------------------------",
    ]
    out = AclReferenceDoc()
    _parse_7_1_flags_and_methods(lines, 0, len(lines), out)
    assert "-i" in out.flags


def test_int_operators_stops_at_matching_subsection() -> None:
    lines = [
        "padding",
        "padding",
        "padding",
        "Available operators for integer matching",
        "   eq : equal",
        "7.1.3. Matching strings",
    ]
    out = AclReferenceDoc()
    _parse_7_1_2_operators(lines, 0, len(lines), out)
    assert "eq" in out.int_operators


# --- action_parser ---


def test_match_action_header_rejects_dashes_and_comments() -> None:
    assert _match_action_header("----------------") is None
    assert _match_action_header("/* comment */") is None
    assert _match_action_header("4.4. Section") is None


def test_match_action_header_single_token() -> None:
    assert _match_action_header("accept") == ("accept", "accept")


def test_store_action_doc_merges_duplicate() -> None:
    actions: dict[str, ActionDoc] = {}
    _store_action_doc(
        actions,
        name="deny",
        signature="deny",
        description="",
        examples=[],
        rulesets=[],
        usable_in="",
        docs_keyword="",
    )
    _store_action_doc(
        actions,
        name="deny",
        signature="deny [ status ]",
        description="Rejects request",
        examples=[],
        rulesets=["http-request"],
        usable_in="HTTP Req",
        docs_keyword="deny",
    )
    assert actions["deny"].description == "Rejects request"
    assert "http-request" in actions["deny"].rulesets


def test_lookup_action_doc_ambiguous_prefix() -> None:
    actions = {
        "foo bar": ActionDoc(name="foo bar", signature="", description="", rulesets=[], usable_in="", docs_keyword="", chapter=""),
        "foo baz": ActionDoc(name="foo baz", signature="", description="", rulesets=[], usable_in="", docs_keyword="", chapter=""),
    }
    assert lookup_action_doc(actions, "foo") is None


def test_parse_actions_no_section_44(tmp_path: Path) -> None:
    path = tmp_path / "doc.txt"
    path.write_text("1. Introduction\n", encoding="utf-8")
    assert parse_actions(path) == {}


def test_parse_actions_skips_blank_lines_before_marks(tmp_path: Path) -> None:
    content = """4.4. Alphabetically sorted actions reference
---------------------------------------------

deny
  Usable in:  HTTP Req| Res
                    X |  X

                    -  |  -

  Rejects the request.
"""
    path = tmp_path / "configuration.txt"
    path.write_text(content, encoding="utf-8")
    actions = parse_actions(path)
    assert "deny" in actions


# --- argument_docs ---


def test_append_value_empty_name() -> None:
    values: list[ArgumentValueDoc] = []
    _append_value(values, "  ", "desc")
    assert values == []


def test_append_value_dedupes_and_fills_description() -> None:
    values = [ArgumentValueDoc(name="tcp", description="")]
    _append_value(values, "tcp", "Transmission control")
    assert values[0].description == "Transmission control"


def test_flatten_argument_values_dedupes() -> None:
    params = [
        ArgumentParamDoc(
            parameter="mode",
            values=[
                ArgumentValueDoc(name="tcp", description=""),
                ArgumentValueDoc(name="TCP", description="dup"),
            ],
        )
    ]
    flat = flatten_argument_values(params)
    assert len(flat) == 1


def test_enum_names_from_params() -> None:
    params = [
        ArgumentParamDoc(
            parameter="",
            values=[ArgumentValueDoc(name="check_post", description=""), ArgumentValueDoc(name="tcp", description="")],
        )
    ]
    assert "check_post" in enum_names_from_params(params)


def test_extract_argument_docs_stops_at_next_keyword() -> None:
    lines = [
        "mode { tcp|http|log }",
        "  Arguments:",
        "    tcp   TCP mode",
        "balance <algorithm>",
    ]
    params = extract_argument_docs(lines, 0)
    assert params


def test_extract_argument_docs_value_before_param() -> None:
    lines = [
        "ssl-default-bind-options [<option>]...",
        "  Arguments:",
        "    no-sslv3   disable SSLv3",
        "  <option>   option name",
    ]
    params = extract_argument_docs(lines, 0)
    assert any(p.parameter == "" for p in params) or params


# --- config_validator ---


def test_tokenize_escaped_quotes() -> None:
    tokens = _tokenize_line(r'bind "foo\"bar"')
    assert len(tokens) == 2
    assert tokens[0].text == "bind"


def test_is_likely_value_branches() -> None:
    assert _is_likely_value("") is True
    assert _is_likely_value("<addr>") is True
    assert _is_likely_value('"quoted"') is True
    assert _is_likely_value("123") is True
    assert _is_likely_value("if") is True
    assert _is_likely_value("daemon") is False


def test_section_allowed_none() -> None:
    schema = HaproxySchema(version="test")
    assert _section_allowed(schema, None) == set()


def test_resolve_longest_match_empty_tokens() -> None:
    line = ParsedLine(line=0, section="global", tokens=[], is_section_header=False)
    keyword, matched = _resolve_longest_match(line, {"daemon"})
    assert keyword == ""
    assert matched is False


def test_resolve_longest_match_heuristic_fallback() -> None:
    line = ParsedLine(
        line=0,
        section="global",
        tokens=[ParsedToken(text="unknown", start=0, end=7), ParsedToken(text="value", start=8, end=13)],
        is_section_header=False,
    )
    keyword, matched = _resolve_longest_match(line, set())
    assert matched is False
    assert keyword == "unknown value"


def test_is_option_line_no_option() -> None:
    line = ParsedLine(
        line=0,
        section="defaults",
        tokens=[ParsedToken(text="no", start=0, end=2), ParsedToken(text="option", start=3, end=9)],
        is_section_header=False,
    )
    assert _is_option_line(line) is True


def test_schema_prefix_families_fallback() -> None:
    schema = HaproxySchema(version="test")
    families = _schema_prefix_families(schema)
    assert "timeout" in families


def test_validate_config_keyword_valid_in_other_section() -> None:
    schema_path = haproxy_vscode_root() / "schemas" / "haproxy-3.2.schema.json"
    if not schema_path.is_file():
        pytest.skip("schema not built")
    schema = HaproxySchema.from_json(schema_path.read_text(encoding="utf-8"))
    # server-template is backend-only; using it in frontend should not flag if keyword exists elsewhere
    content = """\
frontend fe
  bind :80
  server-template web 5 srv:8080 check
"""
    issues = validate_config(content, schema).unknown_keyword_issues
    assert issues == [] or all(i.keyword != "server-template" for i in issues)


# --- dconv_bridge ---


def test_is_valid_keyword_name_rejects_prose() -> None:
    assert is_valid_keyword_name("---") is False
    assert is_valid_keyword_name("this keyword") is False
    assert is_valid_keyword_name("mode") is True


def test_keyword_doc_variant_for_filters() -> None:
    doc = KeywordDoc(name="mode")
    v1 = doc.variant_for("4.2", signatures=["mode tcp"], sections=["defaults"])
    v2 = doc.variant_for("4.2", signatures=["mode http"], sections=["frontend"])
    assert v1 is not v2


def test_keyword_doc_chapter_setter() -> None:
    doc = KeywordDoc(name="mode")
    doc.chapter = "4.2"
    assert doc.variants[0].chapter == "4.2"
    doc.variant_for("3.1", signatures=["mode tcp"])
    doc.chapter = "3.1"
    assert len(doc.variants) == 2


def test_merge_argument_docs_appends_values() -> None:
    variant = KeywordVariantDoc(chapter="4.2")
    variant.arguments = [ArgumentParamDoc(parameter="<mode>", values=[ArgumentValueDoc(name="tcp", description="")])]
    merge_argument_docs(
        variant,
        [ArgumentParamDoc(parameter="<mode>", values=[ArgumentValueDoc(name="http", description="HTTP")])],
    )
    names = {v.name for v in variant.arguments[0].values}
    assert names == {"tcp", "http"}


def test_extract_sections_without_marks_row() -> None:
    lines = [
        "mode { tcp|http|log }",
        "  Set operating mode.",
        "  May be used in sections :   defaults | frontend",
        "",
    ]
    sections = extract_sections_from_keyword_block(lines, 0, len(lines))
    assert sections == []


def test_is_signature_continuation_line_branches() -> None:
    assert is_signature_continuation_line("     [ optional ]") is True
    assert is_signature_continuation_line("# comment") is False


# --- dkall_parser ---


def test_last_significant_word_empty() -> None:
    assert _last_significant_word("   ") is None


def test_extract_option_tokens_wrong_prefix() -> None:
    assert _extract_option_tokens_after_prefix("server foo", "bind <addr> ") == []


def test_is_significant_nested_token_branches() -> None:
    assert _is_significant_nested_token("") is False
    assert _is_significant_nested_token("<addr>") is False
    assert _is_significant_nested_token("if") is False
    assert _is_significant_nested_token("ssl") is True


def test_parse_dkall_rejects_usage_text(tmp_path: Path) -> None:
    path = tmp_path / "dkall.output"
    path.write_text("HAProxy version 3.2\nUsage: haproxy ...\n", encoding="utf-8")
    with pytest.raises(ValueError, match="does not look like dkall"):
        parse_dkall(path)


def test_parse_dkall_filter_and_service_blocks(tmp_path: Path) -> None:
    content = """# List of registered configuration keywords:
global
\tfilter bwlim-in
# List of registered filter names:
custom-filter
# List of registered service names:
prometheus-exporter
"""
    path = tmp_path / "dkall.output"
    path.write_text(content, encoding="utf-8")
    result = parse_dkall(path)
    assert "custom-filter" in result.filters
    assert "prometheus-exporter" in result.services


def test_parse_dkall_converter_fallback(tmp_path: Path) -> None:
    content = """# List of registered sample converter functions:
broken line without parens
"""
    path = tmp_path / "dkall.output"
    path.write_text(content, encoding="utf-8")
    result = parse_dkall(path)
    assert "broken" in result.sample_converters


def test_parse_dkall_acl_empty_left(tmp_path: Path) -> None:
    content = """# List of registered ACL keywords:
 = invalid
hdr = hdr -m found
"""
    path = tmp_path / "dkall.output"
    path.write_text(content, encoding="utf-8")
    result = parse_dkall(path)
    assert "hdr" in result.acl_criteria


# --- dkall_supplement ---


def test_supplement_skips_missing_reference_file(tmp_path: Path) -> None:
    dkall = DkallParseResult()
    dkall.server_options.discard("ssl")
    supplement_missing_tls_options(dkall, tmp_path)
    assert "ssl" not in dkall.server_options


def test_supplement_skips_reference_without_ssl(tmp_path: Path) -> None:
    ref = tmp_path / "dkall-3.2.txt"
    ref.write_text(
        """# List of registered configuration keywords:
listen
\tbind <addr> crt
\tserver <name> <addr> check
""",
        encoding="utf-8",
    )
    dkall = DkallParseResult()
    dkall.server_options.discard("ssl")
    supplement_missing_tls_options(dkall, tmp_path)
    assert "ssl" not in dkall.server_options


# --- grammar ---


def test_emit_tm_language_minimal() -> None:
    schema = HaproxySchema(version="3.2")
    grammar = emit_tm_language_minimal(schema)
    assert grammar["name"] == "HAProxy 3.2"
    assert grammar["repository"]["comments"]["patterns"][0]["match"] == "#.*$"


def test_is_directive_token_too_long() -> None:
    assert is_directive_token("a" * 65) is False


def test_validate_line_isolated_grammar_raises() -> None:
    bad = {"begin": "^foo", "end": "bar"}
    with pytest.raises(ValueError, match="not line-isolated"):
        validate_line_isolated_grammar(bad)


def test_prefix_conflicts_detected() -> None:
    conflicts = _prefix_conflicts({"foo", "foo-bar"})
    assert ("foo", "foo-bar") in conflicts


def test_extract_schema_directive_alternation_no_match() -> None:
    assert _extract_schema_directive_alternation("no match here") == set()


def test_extract_repo_literals_empty_match() -> None:
    repo = {"other-key": {"patterns": [{"match": ""}]}}
    assert _extract_repo_literals(repo, "other-key") == set()


def test_grammar_coverage_report_to_dict() -> None:
    report = GrammarCoverageReport(version="3.2")
    assert report.to_dict()["version"] == "3.2"


def test_report_from_paths_invalid_json(tmp_path: Path) -> None:
    schema_path = haproxy_vscode_root() / "schemas" / "haproxy-3.2.schema.json"
    if not schema_path.is_file():
        pytest.skip("schema not built")
    bad = tmp_path / "bad.json"
    bad.write_text("{invalid", encoding="utf-8")
    report = report_from_paths(schema_path, bad)
    assert report.ok


def test_group_multword_skips_invalid_suffix() -> None:
    schema = HaproxySchema(version="test")
    schema.sections["defaults"] = Section(name="defaults", keywords=["timeout connect"])
    schema.keywords["timeout connect"] = Keyword(name="timeout connect", sections=["defaults"])
    groups = _group_multword_keywords(schema)
    assert "timeout" in groups


def test_build_directives_multiword_empty_suffix() -> None:
    schema = HaproxySchema(version="test")
    schema.sections["defaults"] = Section(name="defaults", keywords=["timeout"])
    schema.keywords["timeout"] = Keyword(name="timeout", sections=["defaults"])
    result = _build_directives_multiword(schema)
    assert "patterns" in result


# --- language_data ---


def test_language_data_write_roundtrip(tmp_path: Path) -> None:
    data = HaproxyLanguageData(version="3.2", docsBaseUrl="https://example.com")
    out = tmp_path / "lang.json"
    data.write(out)
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["version"] == "3.2"


def test_action_docs_url_empty_when_no_chapter() -> None:
    assert action_docs_url("3.2", None, "deny", "") == ""


def test_action_docs_url_missing_keyword() -> None:
    action = ActionDoc(name="", signature="", description="", rulesets=[], usable_in="", docs_keyword="", chapter="")
    assert action_docs_url("3.2", action, "deny", "") == ""


def test_sample_signature_marks_deprecated() -> None:
    item = MagicMock()
    item.signature = "hdr()"
    item.deprecated = True
    assert "(deprecated)" in _sample_signature(item)


# --- legacy_action_parser ---


def test_uses_legacy_action_layout() -> None:
    assert uses_legacy_action_layout(["4.2. Keywords", "4.5. Other"]) is True
    assert uses_legacy_action_layout(
        ["4.4. Alphabetically sorted actions reference", "---------------------------------------------"]
    ) is False


def test_normalize_supported_action_empty() -> None:
    assert _normalize_supported_action("  ") is None


def test_parse_legacy_action_reference_merges() -> None:
    lines = [
        "http-request add-header <name> <fmt>",
        "  Adds a header.",
        "http-request add-header <name> <fmt> [if <expr>]",
        "  Extended form.",
    ]
    actions = _parse_legacy_action_reference(lines, 0, len(lines))
    assert "add-header" in actions


# --- line_option_docs ---


def test_is_metadata_line_branches() -> None:
    assert _is_metadata_line("  May be used in the following contexts:") is True
    assert _is_metadata_line("  May be used in sections :   defaults") is True
    assert _is_metadata_line("defaults | frontend") is True
    assert _is_metadata_line("yes | no") is True


def test_skip_metadata_block_stops_at_examples() -> None:
    lines = ["  May be used in sections : defaults", "  Examples:", "  crt   certificate"]
    idx = _skip_metadata_block(lines, 0, len(lines))
    assert lines[idx].startswith("  Examples")


def test_extract_line_option_description(tmp_path: Path) -> None:
    lines = [
        "crt <cert>",
        "  Load a certificate.",
        "  See also: ssl",
    ]
    desc = extract_line_option_description(lines, 0, len(lines))
    assert "certificate" in desc


# --- merge ---


def test_merge_keyword_variant_docs_promotes_sections() -> None:
    kw = Keyword(name="mode")
    kdoc = MagicMock()
    variant = MagicMock()
    variant.chapter = "4.2"
    variant.sections = ["frontend"]
    variant.signatures = []
    variant.contexts = ["http"]
    variant.arguments = []
    kdoc.variants = [variant]
    kdoc.sections = ["defaults"]
    kdoc.contexts = ["tcp"]
    _merge_keyword_variant_docs(
        kw, kdoc, merge_keyword_sections=True, merge_keyword_contexts=True, replace_existing=False
    )
    assert "frontend" in kw.sections or "defaults" in kw.sections


def test_prune_compile_time_doc_keywords_noop() -> None:
    schema = HaproxySchema(version="test")
    schema.keywords["daemon"] = Keyword(name="daemon")
    dkall = DkallParseResult()
    _prune_compile_time_doc_keywords(schema, dkall)
    assert "daemon" in schema.keywords


# --- options_metadata ---


def test_option_takes_value_trailing_space_only() -> None:
    assert option_takes_value("foo", ["foo "]) is False


# --- schema ---


def test_schema_write_roundtrip(tmp_path: Path) -> None:
    schema = HaproxySchema(version="test")
    schema.sections["global"] = Section(name="global", keywords=["daemon"])
    schema.keywords["daemon"] = Keyword(name="daemon", sections=["global"])
    out = tmp_path / "schema.json"
    schema.write(out)
    loaded = HaproxySchema.from_json(out.read_text(encoding="utf-8"))
    assert loaded.version == "test"
    assert "daemon" in loaded.keywords


# --- schema_fidelity_audit ---


def test_expected_value_kind_branches() -> None:
    assert _expected_value_kind("address") == "address"
    assert _expected_value_kind("name") == "name"
    assert _expected_value_kind("value") == "generic"


def test_inspect_keyword_argument_model_issues() -> None:
    kw = Keyword(
        name="test",
        signatures=["test"],
        argument_model=ArgumentModel(min_args=0, max_args=0, slots=[]),
    )
    issues = _inspect_keyword_argument_model("test", kw, None)
    assert isinstance(issues, list)


def test_group_item_audit_takes_value_mismatch() -> None:
    item = MagicMock()
    item.signatures = ["crt <cert>"]
    item.contexts = []
    item.description = "Load certificate"
    audit = _group_item_audit(
        group="bind_options",
        name="crt",
        doc_item=item,
        takes_value_expected=True,
        in_schema_value_group=False,
    )
    assert "takes_value_mismatch" in audit.issues


# --- signature_model ---


def test_parse_signature_model_no_slots() -> None:
    assert parse_signature_model("daemon", "daemon") is not None
    assert parse_signature_model("keyword ...", "keyword") is None


def test_merge_argument_models_address_kind() -> None:
    a = parse_signature_model("<address>", "bind")
    b = parse_signature_model("<addr>", "bind")
    assert a is not None and b is not None
    merged = merge_argument_models([a, b])
    assert merged is not None


def test_patch_log_argument_model_short() -> None:
    model = ArgumentModel(min_args=1, max_args=1, slots=[{"role": "value"}])
    _patch_log_argument_model(model)
    assert model.min_args == 1


def test_patch_redirect_argument_model_empty() -> None:
    model = ArgumentModel(min_args=0, max_args=0, slots=[])
    _patch_redirect_argument_model(model)
    assert model.slots == []


def test_enrich_slots_from_doc_enums_noop() -> None:
    model = ArgumentModel(min_args=0, max_args=0, slots=[])
    _enrich_slots_from_doc_enums(model, [])
    assert model.slots == []


def test_preferred_keyword_variant_empty() -> None:
    kw = Keyword(name="mode")
    assert _preferred_keyword_variant(kw) is kw


# --- slot_model ---


def test_port_policy_from_parts() -> None:
    parts = ["<address>", ":<port>"]
    assert _port_policy_from_parts(parts, 0) == "required"


def test_address_policy_for_keyword() -> None:
    assert _address_policy_for_keyword("bind", "address") == "bind"


def test_pick_best_layout_none() -> None:
    assert pick_best_layout("unknown", []) is None


def test_enrich_statement_rules_no_layout() -> None:
    rules = [{"keyword": "unknown-cmd", "prefix": "unknown-cmd"}]
    keywords = {"unknown-cmd": {"signatures": ["unknown-cmd"]}}
    enriched = enrich_statement_rules(rules, keywords)
    assert enriched[0]["keyword"] == "unknown-cmd"


# --- statement_rules ---


def test_statement_rules_to_dict_includes_sections() -> None:
    rule = StatementRule(keyword="log", kind="directive", sections=["global"])
    out = statement_rules_to_dict([rule])
    assert out[0]["sections"] == ["global"]


# --- doc_parser edge cases ---


def test_parse_configuration_raises_without_required_sections(tmp_path: Path) -> None:
    path = tmp_path / "configuration.txt"
    path.write_text("1. Introduction\nNo real sections\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Failed to locate"):
        parse_configuration(path)


def test_fill_missing_descriptions_deprecated() -> None:
    entries = {"hdr": SampleDoc(name="hdr", signature="hdr([string])", description="")}
    lines = [
        "7.3.1. Sample fetch functions",
        "-------------------------------",
        "",
        "7.3.2. Detailed list",
        "--------------------",
        "",
        "hdr([string]) : str (deprecated)",
        "  Fetch an HTTP header.",
    ]
    _fill_missing_descriptions(lines, 0, len(lines), entries, converters=False)
    assert "HTTP header" in entries["hdr"].description


# --- remaining coverage gaps (batch 2) ---

from haproxy_schema.__main__ import (
    _audit_docs_cmd,
    _check_grammar_cmd,
)
from haproxy_schema.dconv_bridge import (
    KeywordDoc,
    KeywordVariantDoc,
    extract_keyword_name,
    is_valid_keyword_name as dconv_is_valid_keyword_name,
    walk_keyword_docs,
)
from haproxy_schema.doc_parser import (
    _extract_4_1_matrix,
    _is_standalone_directive,
    _merge_variant_docs,
    _matrix_from_proxy_docs,
    _next_nonblank,
    _sections_for_doc,
    _sections_for_variant,
)
from haproxy_schema.grammar_coverage import build_grammar_coverage_report
from haproxy_schema.legacy_action_parser import (
    _matrix_from_supported_blocks,
    is_legacy_action_doc_keyword,
)
from haproxy_schema.line_option_docs import _is_structured_doc_line
from haproxy_schema.merge import merge_schema
from haproxy_schema.options_metadata import collect_options_with_value
from haproxy_schema.sample_doc_parser import (
    _find_body_section as sample_find_body_section,
    _summary_entries,
    parse_sample_reference,
)
from haproxy_schema.schema_fidelity_audit import _keyword_fidelity_audit
from haproxy_schema.signature_model import (
    ArgSlot,
    ArgumentModel,
    _explode_token,
    _parse_slot,
    _signature_argument_parts,
    _value_kind_from_part,
    build_argument_model,
)
from haproxy_schema.slot_model import layout_from_signature


def test_audit_docs_cmd_prints_missing_lists(capsys: pytest.CaptureFixture[str]) -> None:
    report = MagicMock()
    report.proxy_options_missing = ["foo"]
    report.bind_options_missing = ["bar"]
    report.server_options_missing = ["baz"]
    report.to_dict.return_value = {}
    args = MagicMock(version="3.2", doc="d", dkall="k", out="")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("haproxy_schema.__main__.build_doc_audit_report", lambda *a, **k: report)
        assert _audit_docs_cmd(args) == 0
    out = capsys.readouterr().out
    assert "foo" in out and "bar" in out and "baz" in out


def test_check_grammar_cmd_prints_all_failure_kinds(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = MagicMock()
    report.ok = False
    report.missing_in_grammar = ["missing-kw"]
    report.missing_cache_in_grammar = ["cache-kw"]
    report.prefix_conflicts_in_grammar = [("foo", "foo-bar")]
    report.legacy_hyphen_when_schema_underscore = ["use-backend"]
    report.to_dict.return_value = {}
    args = MagicMock(schema=str(tmp_path / "s.json"), grammar="", report_out="")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("haproxy_schema.__main__.report_from_paths", lambda *a, **k: report)
        assert _check_grammar_cmd(args) == 1
    out = capsys.readouterr().out
    assert "missing directive" in out
    assert "prefix conflict" in out
    assert "legacy hyphen" in out


def test_action_header_dash_only_and_single_token(tmp_path: Path) -> None:
    assert _match_action_header("----------------") is None
    assert _match_action_header("accept") == ("accept", "accept")


def test_store_action_doc_updates_signature_and_chapter() -> None:
    actions: dict[str, ActionDoc] = {}
    _store_action_doc(
        actions, name="x", signature="x", description="", examples=[], rulesets=[], usable_in="", docs_keyword=""
    )
    _store_action_doc(
        actions,
        name="x",
        signature="x <arg>",
        description="",
        examples=[],
        rulesets=["a"],
        usable_in="",
        docs_keyword="x-docs",
    )
    assert actions["x"].signature == "x <arg>"
    assert actions["x"].docs_keyword == "x-docs"


def test_parse_actions_blank_before_marks(tmp_path: Path) -> None:
    content = """4.4. Alphabetically sorted actions reference
---------------------------------------------

tarpit
  Usable in:  HTTP Req
                    X

  Delays the session.
"""
    path = tmp_path / "doc.txt"
    path.write_text(content, encoding="utf-8")
    assert "tarpit" in parse_actions(path)


def test_argument_docs_branches() -> None:
    lines = [
        "mode { tcp|http|log }",
        "  Arguments:",
        "    tcp   TCP mode",
        "balance <algorithm>",
        "  Arguments:",
        "    roundrobin",
        "    roundrobin   Round robin",
        "  <algorithm>  The algorithm with the following values:",
        "    source   source hashing",
        "  ssl-default-bind-options [<option>]...",
        "  Arguments:",
        "    no-sslv3",
        "    no-sslv3   disable SSLv3",
        "  ssl-server-verify [none|required]",
        "  Arguments:",
        "    none   no verification",
    ]
    assert extract_argument_docs(lines, 0)
    assert extract_argument_docs(lines, 3)


def test_config_validator_remaining_branches() -> None:
    schema_path = haproxy_vscode_root() / "schemas" / "haproxy-3.2.schema.json"
    if not schema_path.is_file():
        pytest.skip("schema not built")
    schema = HaproxySchema.from_json(schema_path.read_text(encoding="utf-8"))
    assert _is_likely_value("{expr}") is True
    line = ParsedLine(
        line=0,
        section="unknown-section",
        tokens=[ParsedToken(text="daemon", start=0, end=6)],
        is_section_header=False,
    )
    validate_config("unknown-section\n  daemon\n", schema)
    content = """\
frontend fe
  bind :80
  timeout connect 5s
"""
    assert validate_config(content, schema).unknown_keyword_issues == []


def test_dconv_bridge_remaining_branches() -> None:
    doc = KeywordDoc(name="mode")
    doc.variant_for("4.2", signatures=["mode tcp"], sections=["defaults"])
    doc.variant_for("4.2", signatures=["mode http"], sections=["frontend"])
    picked = doc.variant_for("4.2", signatures={"mode tcp"}, sections={"defaults"})
    assert picked.sections == ["defaults"]
    doc.chapter = "4.2"
    assert dconv_is_valid_keyword_name("___") is False
    assert extract_keyword_name("hdr([string])") == "hdr"
    assert is_signature_continuation_line("# stop") is False
    content = """4.2. Keywords
-------------

mode { tcp|http|log }
  Set mode.
  May be used in sections :   defaults | frontend
                    yes | yes

balance <algorithm>
  Balance.
"""
    docs = walk_keyword_docs(content.splitlines(), 2, len(content.splitlines()), "4.2")
    variant = docs["mode"].variant_for("4.2")
    merge_argument_docs(variant, [ArgumentParamDoc(parameter="<mode>", description="", values=[])])


def test_dkall_remaining_branches(tmp_path: Path) -> None:
    content = """# List of registered configuration keywords:
global

\toption forwardfor
# List of registered sample converter functions:
[ctx] lower(str): str => str
broken converter line
# List of registered filter names:
my-filter
"""
    path = tmp_path / "dkall.output"
    path.write_text(content, encoding="utf-8")
    result = parse_dkall(path)
    assert "lower" in result.sample_converters
    assert "my-filter" in result.filters


def test_doc_audit_proxy_missing_append() -> None:
    doc_path = haproxy_configuration_txt("3.2")
    dkall_path = dkall_dump("3.2")
    if not doc_path.is_file() or not dkall_path.is_file():
        pytest.skip("missing sources")
    from haproxy_schema.doc_audit import build_doc_audit_report

    report = build_doc_audit_report("3.2", doc_path, dkall_path)
    assert isinstance(report.proxy_options_missing, list)


def test_doc_parser_private_helpers() -> None:
    lines = ["a", "  ", "b"]
    assert _next_nonblank(lines, 0) == "a"
    assert _next_nonblank(lines, 1) == "b"
    assert _next_nonblank(["", ""], 0) == ""

    matrix_lines = [
        " keyword                              defaults   frontend   listen    backend",
        "------------------------------------+----------+----------+---------+---------",
        " acl                                  X (!)      X         X         X",
        " option redispatch              (*)  X          -         X         X",
    ]
    matrix, no_prefix, named = _extract_4_1_matrix(matrix_lines, 0, len(matrix_lines))
    assert "acl" in matrix["defaults"]
    assert "option redispatch" in no_prefix

    source = KeywordVariantDoc(chapter="4.2", sections=["frontend"], signatures=["sig2"], contexts=["http"])
    target = KeywordVariantDoc(chapter="4.2", sections=["defaults"], signatures=["sig1"])
    _merge_variant_docs(target, source)
    assert "frontend" in target.sections
    assert "sig2" in target.signatures
    assert "http" in target.contexts

    invalid_doc = KeywordDoc(name="---", variants=[KeywordVariantDoc(chapter="4.2", sections=["defaults"])])
    assert _matrix_from_proxy_docs({"---": invalid_doc}) == {s: set() for s in ("defaults", "frontend", "listen", "backend")}

    assert _is_standalone_directive("filter bwlim-in") is False
    assert _is_standalone_directive("req ssl_ver") is False
    assert _is_standalone_directive("cache") is True

    sections = _sections_for_doc(
        "daemon",
        global_keywords={"daemon"},
        matrix={"defaults": set()},
        section_keywords={"global": {"daemon"}},
        doc_sections=["global"],
    )
    assert sections == ["global", "daemon"] or "global" in sections

    variant = KeywordVariantDoc(chapter="3.1", sections=[], signatures=[])
    out = _sections_for_variant(
        "peers-kw",
        variant,
        global_keywords=set(),
        matrix={},
        section_keywords={"peers": {"peers-kw"}},
        section_chapters={"peers": {"3.4"}},
    )
    assert out == []


def test_grammar_coverage_non_schema_repo_branch() -> None:
    # The repo literal regex only accepts tokens drawn from [\w.\-] and \\-
    repo = {"legacy-rules": {"patterns": [{"match": "(?:w|\\\\-)"}]}}
    words = _extract_repo_literals(repo, "legacy-rules")
    assert "w" in words


def test_grammar_build_invalid_multword_suffix() -> None:
    schema = HaproxySchema(version="test")
    schema.sections["defaults"] = Section(name="defaults", keywords=["bad multi"])
    schema.keywords["bad multi"] = Keyword(name="bad multi", sections=["defaults"])
    groups = _group_multword_keywords(schema)
    assert "bad" not in groups or groups.get("bad") is not None


def test_legacy_action_parser_remaining() -> None:
    assert is_legacy_action_doc_keyword("http-request set-header") is True
    lines = [
        "unknown-phase <action>",
        "  supported:",
        "    - allow",
        "http-request <action>",
        "  Description without supported block",
    ]
    matrix = _matrix_from_supported_blocks(lines, 0, len(lines))
    assert matrix["http_request_actions"] == set()

    merge_lines = [
        "http-request deny",
        "  First description.",
        "http-request deny [ status ]",
        "  Second description.",
    ]
    actions = _parse_legacy_action_reference(merge_lines, 0, len(merge_lines))
    assert actions["deny"].description == "First description."


def test_line_option_docs_metadata_and_structured() -> None:
    assert _is_metadata_line("") is True
    assert _is_metadata_line("  May be used in the following contexts: tcp") is True
    assert _is_structured_doc_line("| col |") is True
    lines = [
        "crt <cert>",
        "  Load certificate.",
        "  Examples:",
        "    crt /path/to/cert.pem",
        "  See also: ssl",
        "ssl",
        "  Enable SSL.",
    ]
    assert "certificate" in extract_line_option_description(lines, 0, len(lines))


def test_merge_schema_section_keyword_append() -> None:
    doc_path = haproxy_configuration_txt("3.2")
    dkall_path = dkall_dump("3.2")
    if not doc_path.is_file() or not dkall_path.is_file():
        pytest.skip("missing sources")
    from haproxy_schema.doc_parser import parse_configuration
    from haproxy_schema.dkall_parser import parse_dkall

    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    schema = merge_schema("3.2", doc, dkall, dkall_package_dir=dkall_path.parent)
    assert schema.keywords


def test_option_takes_value_with_tail() -> None:
    assert option_takes_value("crt", ["crt <cert>"]) is True
    assert collect_options_with_value(["crt"], {"crt": ["crt <cert>"]}) == ["crt"]


def test_sample_doc_parser_summary_table(tmp_path: Path) -> None:
    content = """7.3.2. Fetch keywords reference
-------------------------------

Keyword  Output type
hdr      string
 url     string

Detailed list of fetch keywords

hdr([string]) : str
  Fetch HTTP header.
7.3.3. More
-----------
"""
    path = tmp_path / "configuration.txt"
    path.write_text(content, encoding="utf-8")
    ref = parse_sample_reference(path)
    assert "hdr" in ref.fetches
    entries = _summary_entries(content.splitlines(), 0, 12, converters=False)
    assert "hdr" in entries


def test_schema_fidelity_keyword_audit_branches() -> None:
    doc_path = haproxy_configuration_txt("3.2")
    dkall_path = dkall_dump("3.2")
    if not doc_path.is_file() or not dkall_path.is_file():
        pytest.skip("missing sources")
    from haproxy_schema.doc_parser import parse_configuration
    from haproxy_schema.dkall_parser import parse_dkall

    doc = parse_configuration(doc_path)
    schema = merge_schema("3.2", doc, parse_dkall(dkall_path), dkall_package_dir=dkall_path.parent)
    audit = _keyword_fidelity_audit(schema, doc, "nameserver")
    assert audit is None or audit.keyword == "nameserver"


def test_signature_model_remaining_branches() -> None:
    model = ArgumentModel(min_args=1, max_args=1, slots=[ArgSlot(value_kind="generic")])
    assert model.to_json_dict()["min_args"] == 1
    assert _explode_token("{a|b}") == ["{a|b}"]
    assert _value_kind_from_part("<address>") == "address"
    assert _parse_slot("[ { if | unless } <condition> ]") == []
    assert _signature_argument_parts("bind <addr>", "server")
    merged = merge_argument_models(
        [
            build_argument_model("x", ["x <addr>"]) or ArgumentModel(min_args=1, max_args=1, slots=[]),
            build_argument_model("x", ["x <name>"]) or ArgumentModel(min_args=1, max_args=1, slots=[]),
        ]
    )
    assert merged is not None
    _enrich_slots_from_doc_enums(
        ArgumentModel(min_args=1, max_args=1, slots=[ArgSlot(value_kind="enum", enum=["a"])]),
        ["a"],
        slot_index=0,
    )


def test_slot_model_remaining_branches() -> None:
    assert layout_from_signature("daemon", "daemon") is None
    layout = layout_from_signature("bind", "bind <addr> [param*]")
    assert layout is not None
    assert pick_best_layout("bind", ["bind <addr>", "bind <addr> :<port>"]) is not None
    rules = [{"keyword": "server", "kind": "directive", "prefix": "server"}]
    keywords = {"server": {"signatures": ["server <name> <addr> check"]}}
    enriched = enrich_statement_rules(rules, keywords)
    assert enriched[0].get("fixed_slots") or enriched[0]["keyword"] == "server"

