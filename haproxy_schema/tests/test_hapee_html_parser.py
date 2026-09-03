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
    assert set(HAPEE_RELEASES) == {"2.6r1", "2.8r1", "3.0r1", "3.2r1"}
    assert HAPEE_RELEASES["2.6r1"].extra_global_chapters == ("3.11",)
    assert HAPEE_RELEASES["2.8r1"].extra_global_chapters == ("3.11",)
    assert HAPEE_RELEASES["3.0r1"].extra_global_chapters == ("3.13",)
    assert HAPEE_RELEASES["3.2r1"].extra_global_chapters == ("3.5",)
    assert HAPEE_RELEASES["3.2r1"].oss_base == "3.2"


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
