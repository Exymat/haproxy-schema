from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from haproxy_schema.hapee_versions import (
    HAPEE_RELEASES,
    HapeeRelease,
    hapee_release,
    verify_hapee_source_text,
)
from haproxy_schema.html_doc_parser import (
    html_to_configuration_lines,
    modules_chapter_id,
    parse_configuration_html,
    parse_sample_reference_html,
)

from ._paths import haproxy_configuration_txt

# Minimal dconv HTML: Modules chapter plus the chapters parse_configuration_lines requires.
_HAPEE_HTML = """
<html><body>
<h2 data-target="3.1" id="chapter-3.1">3.1. Process management and security</h2>
<div class="keyword"><b>51degrees-data-file</b> <span>&lt;file path&gt;</span></div>
<div class="text">The path of the 51Degrees data file.</div>
<h2 data-target="3.4" id="chapter-3.4">3.4. Userlists</h2>
<div class="text">placeholder</div>
<h2 data-target="3.5" id="chapter-3.5">3.5. Modules</h2>
<div class="keyword"><b>module-load</b> <span>&lt;module&gt;</span></div>
<div class="text">Give the module file to load.</div>
<div class="keyword"><b>module-path</b> <span>&lt;directory&gt;</span></div>
<div class="text">Default path for module-load.</div>
<h2 data-target="4.1" id="chapter-4.1">4.1. Proxy keywords matrix</h2>
<table class="table-bordered">
  <tr><th>keyword</th><th>defaults</th><th>frontend</th><th>listen</th><th>backend</th></tr>
  <tr><td>maxconn</td><td>X</td><td>X</td><td>X</td><td>X</td></tr>
</table>
<h2 data-target="4.2" id="chapter-4.2">4.2. Alphabetically sorted keywords reference</h2>
<div class="keyword"><b>maxconn</b> <span>&lt;value&gt;</span></div>
<div class="text">Maximum number of connections.</div>
</body></html>
"""


@pytest.fixture(scope="module")
def oss_configuration_txt() -> Path:
    path = haproxy_configuration_txt("3.2")
    if not path.is_file():
        pytest.skip(f"missing OSS configuration.txt: {path}")
    return path


def test_hapee_releases_cover_lts_and_modules_chapters() -> None:
    assert set(HAPEE_RELEASES) == {"2.6r1", "2.8r1", "3.0r1", "3.2r1", "3.4r1"}
    assert HAPEE_RELEASES["2.6r1"].extra_global_chapters == ("3.11",)
    assert HAPEE_RELEASES["2.8r1"].extra_global_chapters == ("3.11",)
    assert HAPEE_RELEASES["3.0r1"].extra_global_chapters == ("3.13",)
    assert HAPEE_RELEASES["3.2r1"].extra_global_chapters == ("3.5",)
    assert HAPEE_RELEASES["3.2r1"].oss_base == "3.2"
    assert HAPEE_RELEASES["3.4r1"].extra_global_chapters == ("3.5",)
    assert HAPEE_RELEASES["3.4r1"].oss_base == "3.4"


def test_hapee_source_pin_normalizes_line_endings_and_rejects_changes() -> None:
    expected = "first\nsecond\n"
    release = HapeeRelease(
        version="test-r1",
        oss_base="test",
        doc_slug="test",
        source_sha256=hashlib.sha256(expected.encode()).hexdigest(),
    )
    assert verify_hapee_source_text("first\r\nsecond\r\n", release) == expected
    with pytest.raises(ValueError, match="source checksum changed"):
        verify_hapee_source_text("changed\n", release)


def test_html_to_configuration_lines_extracts_module_keywords() -> None:
    lines = html_to_configuration_lines(_HAPEE_HTML)
    text = "\n".join(lines)
    assert "module-load" in text
    assert "module-path" in text
    assert "51degrees-data-file" in text
    assert modules_chapter_id(lines) == "3.5"


def test_parse_configuration_html_keeps_stick_table_key_types(oss_configuration_txt: Path) -> None:
    release = hapee_release("3.2r1")
    doc = parse_configuration_html(_HAPEE_HTML, release=release, oss_reference_doc=oss_configuration_txt)
    stick = doc.keyword_docs["stick-table type"]
    values = {value.name for param in stick.arguments for value in param.values}
    assert {"ip", "ipv4", "ipv6"} <= values
    for variant in stick.variants:
        variant_values = {value.name for param in variant.arguments for value in param.values}
        assert "ip" in variant_values, variant.signatures


def test_html_stick_table_declaration_arguments_survive_conversion() -> None:
    html = """
    <html><body>
    <h2 data-target="3.1" id="chapter-3.1">3.1. Process management and security</h2>
    <div class="text">placeholder</div>
    <h2 data-target="3.4" id="chapter-3.4">3.4. Userlists</h2>
    <div class="text">placeholder</div>
    <h2 data-target="4.1" id="chapter-4.1">4.1. Proxy keywords matrix</h2>
    <table class="table-bordered">
      <tr><th>keyword</th><th>defaults</th><th>frontend</th><th>listen</th><th>backend</th></tr>
      <tr><td>stick-table type</td><td></td><td>X</td><td>X</td><td>X</td></tr>
    </table>
    <h2 data-target="4.2" id="chapter-4.2">4.2. Alphabetically sorted keywords reference</h2>
    <div class="keyword"><b>stick-table</b> type &lt;type&gt; size &lt;size&gt; [expire &lt;expire&gt;] [args...]</div>
    <div class="text">Please refer to section 11.1 for the complete details.</div>
    <h3 data-target="11.1" id="chapter-11.1">11.1. Stick-table declaration</h3>
    <div class="text">In a frontend, backend or listen section:</div>
    <div class="keyword"><b>stick-table</b> type &lt;type&gt; size &lt;size&gt;</div>
    <div class="separator"><span>Arguments:</span>
      <pre class="arguments">  - type &lt;type&gt;
             This mandatory argument sets the key type to &lt;type&gt;, which
             usually is a single word but may also have its own arguments:
     * ip        This type should be avoided in favor of ipv4.
     * ipv4      A table declared with this type will only store IPv4 addresses.
  - size &lt;size&gt;
             This mandatory argument sets maximum number of entries.
</pre>
    </div>
    </body></html>
    """
    from haproxy_schema.stick_table_docs import parse_stick_table_declaration_arguments

    lines = html_to_configuration_lines(html)
    params = parse_stick_table_declaration_arguments(lines)
    names = {value.name for param in params for value in param.values}
    assert "ip" in names
    assert "ipv4" in names
    ip = next(value for param in params for value in param.values if value.name == "ip")
    assert "avoided" in ip.description

    release = hapee_release("3.2r1")
    doc = parse_configuration_html(html, release=release, oss_reference_doc=None)
    values = {value.name for param in doc.keyword_docs["stick-table type"].arguments for value in param.values}
    assert "ip" in values
    assert "ipv4" in values


def test_parse_sample_reference_html_extracts_has_ctl() -> None:
    html = """
    <html><body>
    <h3 id="chapter-7.3.1">7.3.1. Converters</h3>
    <table>
      <tr><th>keyword</th><th>input</th><th>output</th></tr>
      <tr><td>has_ctl(&lt;class&gt;)</td><td>string</td><td>boolean</td></tr>
    </table>
    <div class="keyword"><b>has_ctl</b>(&lt;class&gt;)</div>
    <div class="text">True if the input contains a control character of the given class.</div>
    <h3 id="chapter-7.3.2">7.3.2. Fetching samples</h3>
    </body></html>
    """
    samples = parse_sample_reference_html(html)
    assert "has_ctl" in samples.converters
    assert samples.converters["has_ctl"].chapter == "7.3.1"
    assert "string" in samples.converters["has_ctl"].input_type
    assert "boolean" in samples.converters["has_ctl"].output_type


def test_html_matrix_preserves_empty_columns() -> None:
    html = """
    <html><body>
    <h2 data-target="4.1" id="chapter-4.1">4.1. Proxy keywords matrix</h2>
    <table class="table-bordered">
      <tr><th>keyword</th><th>defaults</th><th>frontend</th><th>listen</th><th>backend</th></tr>
      <tr><td>frontend-only</td><td></td><td>X</td><td></td><td></td></tr>
      <tr><td>backend-only</td><td></td><td></td><td></td><td>X</td></tr>
    </table>
    </body></html>
    """
    text = "\n".join(html_to_configuration_lines(html))
    assert "frontend-only  -  X  -  -" in text
    assert "backend-only  -  -  -  X" in text


def test_sample_parser_ignores_example_tables_and_normalizes_detail_signatures() -> None:
    html = """
    <html><body>
    <h3 id="chapter-7.3.1">7.3.1. Converters</h3>
    <table class="table-bordered">
      <tr><th>keyword</th><th>input type</th><th>output type</th></tr>
      <tr><td>has_ctl([mask])</td><td>string</td><td>boolean</td></tr>
    </table>
    <table><tr><th>Example</th><th>Meaning</th></tr>
      <tr><td>http-response set-header bytes_var1_var3</td><td>example</td></tr>
    </table>
    <div class="keyword"><b>has_ctl</b> ( [mask] ) : boolean</div>
    <div class="text">Checks control characters.</div>
    <h3 id="chapter-7.3.2">7.3.2. Fetches</h3>
    </body></html>
    """
    samples = parse_sample_reference_html(html)
    assert set(samples.converters) == {"has_ctl"}
    assert samples.converters["has_ctl"].signature == "has_ctl([mask])"

@pytest.mark.parametrize(
    "markup, expected",
    [
        ('<b>add-acl</b>(<span>&lt;file-name&gt;</span>) <span>&lt;key fmt&gt;</span>',
         'add-acl(<file-name>) <key fmt>'),
        ('<b>sc-add-gpc</b>(&lt;idx&gt;, &lt;sc-id&gt;) { &lt;int&gt; | &lt;expr&gt; }',
         'sc-add-gpc(<idx>,<sc-id>) { <int> | <expr> }'),
        ('<b>set-var</b>(&lt;var-name&gt; [, &lt;cond&gt; ...]) &lt;expr&gt;',
         'set-var(<var-name>[,<cond>...]) <expr>'),
        ('<b>bind</b> /<span>&lt;path&gt;</span> [param*]',
         'bind /<path> [param*]'),
        ('<b>has_ctl</b> ( [mask] ) : boolean', 'has_ctl([mask]) : boolean'),
        ('<b>old-option</b> &lt;number&gt; (deprecated)',
         'old-option <number> (deprecated)'),
    ],
)
def test_html_signatures_preserve_keyword_boundaries(markup: str, expected: str) -> None:
    from bs4 import BeautifulSoup
    from haproxy_schema.dconv_bridge import match_dconv_keyword_line
    from haproxy_schema.html_doc_parser import _keyword_signature

    node = BeautifulSoup(f'<div class="keyword">{markup}</div>', "html.parser").div
    signature = _keyword_signature(node)
    assert signature == expected
    assert match_dconv_keyword_line(signature) is not None


def test_html_action_descriptions_stop_at_next_keyword_and_skip_usage_tables() -> None:
    from haproxy_schema.action_parser import parse_actions_lines

    html = '''<h2 id="chapter-4.4">4.4. Alphabetically sorted actions reference</h2>
    <div class="keyword"><b>accept</b></div>
    <div><p>Usable in :</p><table class="table-bordered">
      <tr><th>TCP RqCon</th><th>HTTP Req</th></tr>
      <tr><td><img alt="X" title="yes"></td><td>&nbsp;</td></tr>
    </table></div>
    <div class="text">Accept the connection. This description ends here.</div>
    <div class="keyword"><b>add-acl</b>(&lt;file-name&gt;) &lt;key fmt&gt;</div>
    <div class="text">Add an ACL entry. Only add-acl owns this paragraph.</div>
    <div class="keyword"><b>set-var</b>(&lt;name&gt; [, &lt;cond&gt; ...]) &lt;expr&gt;</div>
    <div class="text">Set a variable. Only set-var owns this paragraph.</div>'''
    lines = html_to_configuration_lines(html)
    actions = parse_actions_lines(lines, lines.index("accept"), len(lines))
    assert actions["accept"].description == "Accept the connection. This description ends here."
    assert actions["accept"].rulesets == ["tcp-request connection"]
    assert actions["add-acl"].description == "Add an ACL entry. Only add-acl owns this paragraph."
    assert actions["set-var"].description == "Set a variable. Only set-var owns this paragraph."


def test_html_keyword_sections_and_hidden_link_menus_are_metadata() -> None:
    from haproxy_schema.dconv_bridge import walk_keyword_docs

    html = '''<h2 id="chapter-4.2">4.2. Alphabetically sorted keywords reference</h2>
    <div class="keyword"><b>test-option</b> &lt;value&gt;</div>
    <div><p>May be used in sections :</p><table class="table-bordered">
      <tr><th>defaults</th><th>frontend</th><th>listen</th><th>backend</th></tr>
      <tr><td><img alt="X"></td><td></td><td><img alt="X"></td><td></td></tr>
    </table></div>
    <div class="text">Use <span class="dropdown"><a class="dropdown-toggle">server</a>
      <ul class="dropdown-menu"><li>This keyword is available in sections :</li>
      <li>Secret menu label</li></ul></span> for this setting.</div>'''
    lines = html_to_configuration_lines(html)
    docs = walk_keyword_docs(lines, lines.index("test-option <value>"), len(lines), "4.2")
    assert docs["test-option"].sections == ["defaults", "listen"]
    assert docs["test-option"].description == "Use server for this setting."
    assert "Secret menu label" not in "\n".join(lines)


def test_html_sample_descriptions_exclude_hidden_link_menus() -> None:
    html = '''<h3 id="chapter-7.3.3">7.3.3. Fetching samples at Layer 4</h3>
    <table><tr><th>keyword</th><th>output type</th></tr>
      <tr><td>fc_saved_syn</td><td>binary</td></tr></table>
    <div class="keyword"><b>fc_saved_syn</b> : binary</div>
    <div class="text">Inspect <span class="dropdown"><a>set-var</a>
      <ul class="dropdown-menu"><li>This keyword is available in sections :</li>
      <li>Hidden menu label</li></ul></span> before reading the packet.</div>'''
    doc = parse_sample_reference_html(html)
    assert doc.fetches["fc_saved_syn"].description == "Inspect set-var before reading the packet."


@pytest.mark.parametrize("version", HAPEE_RELEASES)
def test_real_hapee_descriptions_do_not_include_following_entries_or_menus(version: str) -> None:
    from haproxy_schema.action_parser import lookup_action_doc
    from haproxy_schema.hapee_versions import default_hapee_html_fixture

    release = hapee_release(version)
    path = default_hapee_html_fixture(version)
    if not path.is_file():
        pytest.skip(f"cached Enterprise manual unavailable: {path}")
    doc = parse_configuration_html(
        path.read_text(encoding="utf-8"), release=release,
        oss_reference_doc=haproxy_configuration_txt(release.oss_base),
    )
    for name, forbidden in [("accept", "add-acl("), ("del-header", "del-map("),
                             ("del-headers-bin", "del-map(")]:
        action = lookup_action_doc(doc.action_reference, name)
        if action is not None:
            assert forbidden not in action.description, (version, name)
    if release.oss_base in {"2.6", "2.8"}:
        # Chapter 7 converters must not leak into legacy chapter 4.2 directives.
        assert "add_item" not in doc.proxy_keywords
        assert "jwt_verify" not in doc.proxy_keywords
    descriptions = [variant.description for keyword in doc.keyword_docs.values()
                    for variant in keyword.variants]
    descriptions.extend(action.description for action in doc.action_reference.values())
    descriptions.extend(item.description for item in doc.sample_reference.fetches.values())
    descriptions.extend(item.description for item in doc.sample_reference.converters.values())
    assert not any("This keyword is available in sections :" in text for text in descriptions)


def test_deprecated_sample_alias_keeps_its_description_and_deprecation() -> None:
    html = '''<h3 id="chapter-7.3.6">7.3.6. Fetching HTTP samples</h3>
    <table><tr><th>keyword</th><th>output type</th></tr>
      <tr><td>cook([&lt;name&gt;])</td><td>string</td></tr></table>
    <div class="keyword"><b>cook</b>([&lt;name&gt;]) : string
      <span class="label label-warning">(deprecated)</span></div>
    <div class="text">Extract the requested cookie value.</div>'''
    doc = parse_sample_reference_html(html)
    assert doc.fetches["cook"].signature == "cook([<name>])"
    assert doc.fetches["cook"].description == "Extract the requested cookie value."
    assert doc.fetches["cook"].deprecated is True


def test_html_top_level_chapters_stop_legacy_proxy_descriptions() -> None:
    from haproxy_schema.dconv_bridge import extract_description_after_header

    html = '''<h2 id="chapter-4.2">4.2. Proxy keywords</h2>
    <div class="keyword"><b>proxy-option</b></div>
    <div class="text">Only this paragraph belongs to proxy-option.</div>
    <h1 id="chapter-5">5. Bind and server options</h1>
    <div class="text">This introduction belongs to the next chapter.</div>
    <h2 id="chapter-5.1">5.1. Bind options</h2>
    <div class="keyword"><b>bind-option</b></div>
    <div class="text">Only this paragraph belongs to bind-option.</div>'''
    lines = html_to_configuration_lines(html)
    assert "5. Bind and server options" in lines
    assert extract_description_after_header(lines, lines.index("proxy-option")) == (
        "Only this paragraph belongs to proxy-option."
    )
    start, end = lines.index("4.2. Proxy keywords"), lines.index("5. Bind and server options")
    assert "bind-option" not in lines[start:end]


def test_sample_aliases_share_one_description_and_support_headers_without_colons() -> None:
    html = '''<h3 id="chapter-7.3.6">7.3.6. Fetching HTTP samples</h3>
    <table><tr><th>keyword</th><th>output type</th></tr>
      <tr><td>req.cook</td><td>string</td></tr>
      <tr><td>cook</td><td>string</td></tr>
      <tr><td>req.ssl_cipherlist</td><td>binary</td></tr></table>
    <div class="keyword"><b>req.cook</b>([&lt;name&gt;]) : string</div>
    <div class="keyword"><b>cook</b>([&lt;name&gt;]) : string (deprecated)</div>
    <div class="text">Read the requested cookie.</div>
    <div class="keyword"><b>req.ssl_cipherlist</b> binary</div>
    <div class="text">Read the client cipher list.</div>'''
    doc = parse_sample_reference_html(html)
    assert doc.fetches["req.cook"].description == "Read the requested cookie."
    assert doc.fetches["cook"].description == "Read the requested cookie."
    assert doc.fetches["cook"].deprecated is True
    assert doc.fetches["req.ssl_cipherlist"].description == "Read the client cipher list."


def test_summary_only_enterprise_samples_preserve_reference_descriptions() -> None:
    from haproxy_schema.doc_parser import DocParseResult
    from haproxy_schema.html_doc_parser import _overlay_doc_parse_result
    from haproxy_schema.sample_doc_parser import SampleDoc

    base, enterprise = DocParseResult(), DocParseResult()
    base.sample_reference.fetches["example"] = SampleDoc(
        name="example", description="Reference description.", deprecated=True,
    )
    enterprise.sample_reference.fetches["example"] = SampleDoc(
        name="example", signature="example([<name>])",
    )
    merged = _overlay_doc_parse_result(base, enterprise)
    assert merged.sample_reference.fetches["example"].description == "Reference description."
    assert merged.sample_reference.fetches["example"].signature == "example([<name>])"
    assert merged.sample_reference.fetches["example"].deprecated is True
    assert base.sample_reference.fetches["example"].signature == ""
