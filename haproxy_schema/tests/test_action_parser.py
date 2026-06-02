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
  Usable in:  TCP RqCon| RqSes| RqCnt| RsCnt |   HTTP Req| Res| Aft
                    X  |   X  |   X  |   X   |         - |  - |  -

  This stops the evaluation and lets the request pass.
"""
    path = tmp_path / "configuration.txt"
    path.write_text(content, encoding="utf-8")
    actions = parse_actions(path)
    assert "deny" in actions
    assert "accept" in actions
    assert "immediately rejects" in actions["deny"].description
    assert "lets the request pass" in actions["accept"].description
