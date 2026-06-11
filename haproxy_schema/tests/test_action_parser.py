from pathlib import Path

from haproxy_schema.action_parser import parse_actions


def test_parse_actions_snippet(tmp_path: Path) -> None:
    content = """4.4. Alphabetically sorted actions reference
---------------------------------------------

deny [ { status | deny_status } <code> ]
  Usable in:  TCP RqCon| RqSes| RqCnt| RsCnt|    HTTP Req| Res| Aft
                    -  |   -  |   -  |   -  |          X |  X |  -

  This stops the evaluation of the rules and immediately rejects.

accept
  Usable in:  QUIC Ini|    TCP RqCon| RqSes| RqCnt| RsCnt|    HTTP Req| Res| Aft
                    X |          X  |   X  |   X  |   X  |         - |  - |  -

  This stops the evaluation and lets the request pass.
"""
    path = tmp_path / "configuration.txt"
    path.write_text(content, encoding="utf-8")
    actions = parse_actions(path)
    assert "deny" in actions
    assert "accept" in actions
    assert "immediately rejects" in actions["deny"].description
    assert "lets the request pass" in actions["accept"].description
    assert "http-request" in actions["deny"].rulesets
    assert "http-response" in actions["deny"].rulesets
    assert "quic-initial" in actions["accept"].rulesets
    assert "tcp-request connection" in actions["accept"].rulesets


def test_parse_actions_registers_each_alternate_signature(tmp_path: Path) -> None:
    content = """4.4. Alphabetically sorted actions reference
---------------------------------------------

track-sc0 <key> [table <table>]
track-sc1 <key> [table <table>]
  Usable in:  TCP RqCon| RqSes| RqCnt| RsCnt|    HTTP Req| Res| Aft
                    - |          X  |   X  |   -  |          X |  X |  -

  This enables tracking of sticky counters from current request.

set-var(<var-name>) <expr>
set-var-fmt(<var-name>) <fmt>
  This is used to set the contents of a variable.
"""
    path = tmp_path / "configuration.txt"
    path.write_text(content, encoding="utf-8")
    actions = parse_actions(path)
    assert "track-sc0" in actions
    assert "track-sc1" in actions
    assert "sticky counters" in actions["track-sc0"].description
    assert actions["track-sc1"].description == actions["track-sc0"].description
    assert "set-var-fmt" in actions
    assert "set the contents of a variable" in actions["set-var-fmt"].description


def test_parse_actions_reads_four_space_description(tmp_path: Path) -> None:
    content = """4.4. Alphabetically sorted actions reference
---------------------------------------------

set-path <fmt>
  Usable in:  TCP RqCon| RqSes| RqCnt| RsCnt|    HTTP Req| Res| Aft
                    - |          -  |   -  |   -  |          X |  - |  -

    This rewrites the request path with the result of the evaluation of format
    string <fmt>.
"""
    path = tmp_path / "configuration.txt"
    path.write_text(content, encoding="utf-8")
    actions = parse_actions(path)
    assert "rewrites the request path" in actions["set-path"].description
    assert "<fmt>" in actions["set-path"].description


def test_parse_actions_registers_short_config_keyword_alias(tmp_path: Path) -> None:
    content = """4.4. Alphabetically sorted actions reference
---------------------------------------------

wait-for-body time <time> [ at-least <bytes> ]
  Usable in:  TCP RqCon| RqSes| RqCnt| RsCnt|    HTTP Req| Res| Aft
                    - |          -  |   -  |   -  |          X |  X |  -

  This will delay the processing of the request or response.
"""
    path = tmp_path / "configuration.txt"
    path.write_text(content, encoding="utf-8")
    actions = parse_actions(path)
    assert "wait-for-body time" in actions
    assert "wait-for-body" in actions
    assert "delay the processing" in actions["wait-for-body"].description


def test_parse_actions_appends_multiline_signature(tmp_path: Path) -> None:
    content = """4.4. Alphabetically sorted actions reference
---------------------------------------------

deny [ { status | deny_status } <code> ] [ content-type <type> ]
     [ { default-errorfiles | errorfile <file> | errorfiles <name> |
       file <file> | lf-file <file> | string <str> | lf-string <fmt> } ]
     [ hdr <name> <fmt> ]*
  This stops the evaluation of the rules.
"""
    path = tmp_path / "configuration.txt"
    path.write_text(content, encoding="utf-8")
    actions = parse_actions(path)
    assert "lf-string <fmt>" in actions["deny"].signature
    assert "[ hdr <name> <fmt> ]*" in actions["deny"].signature
