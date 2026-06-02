from pathlib import Path

from haproxy_schema.dkall_parser import parse_dkall


def test_parse_dkall_extracts_keyword_groups(tmp_path: Path) -> None:
    content = """# List of registered ACL keywords:
hdr = hdr -m found
path = path -m beg
# List of registered configuration keywords:
global
\tdaemon
listen
\tbind <addr> ssl crt +1
\tserver <name> <addr> check
\tserver <name> <addr> source +-1
\toption forwardfor [ FE HTTP ]
\thttp-request redirect
\thttp-response set-status
\thttp-after-response set-status
\ttcp-request connection do-log
\ttcp-response content reject
\tacl
# List of registered sample converter functions:
lower(str): str => str
regsub(str,str,str): str => str
# List of registered filter names:
bwlim-in
# List of registered sample fetch functions:
[ Y Y . . ] hdr([string]): str
[ Y Y . . ] url: str
# List of registered service names:
prometheus-exporter
"""
    file_path = tmp_path / "dkall.output"
    file_path.write_text(content, encoding="utf-8")

    result = parse_dkall(file_path)

    assert "global" in result.section_keywords
    assert "listen" in result.section_keywords
    assert "bind" in result.section_keywords["listen"]
    assert "server" in result.section_keywords["listen"]
    assert "forwardfor" in result.options
    assert "crt" in result.bind_options
    assert "ssl" in result.bind_options
    assert "check" in result.server_options
    assert "source" in result.server_options
    assert "redirect" in result.http_request_actions
    assert "set-status" in result.http_response_actions
    assert "set-status" in result.http_after_response_actions
    assert "do-log" in result.tcp_request_actions
    assert "prometheus-exporter" in result.services
    assert "hdr" in result.acl_criteria
    assert "lower" in result.sample_converters
    assert "hdr" in result.sample_fetches
    assert "bwlim-in" in result.filters
