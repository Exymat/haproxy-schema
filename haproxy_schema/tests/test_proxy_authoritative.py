from pathlib import Path

from haproxy_schema.doc_parser import parse_configuration

from ._paths import haproxy_configuration_txt


def test_proxy_keywords_include_4_2_only_not_matrix_aggregates() -> None:
    content = haproxy_configuration_txt("3.2")
    if not content.is_file():
        return

    result = parse_configuration(content)
    assert "stats show-modules" in result.proxy_keywords
    assert "stats show-modules" in result.matrix_keywords["frontend"]
    assert "balance" in result.proxy_keywords
    assert "random" in {
        value.name.split("(", 1)[0]
        for param in result.keyword_docs["balance"].arguments
        for value in param.values
    }


def test_action_matrix_includes_4_4_rulesets(tmp_path: Path) -> None:
    content = """Summary
3.1. Process management and security
3.4. Userlists
4.1. Proxy keywords matrix
4.2. Alphabetically sorted keywords reference
4.3. Actions keywords matrix
4.4. Alphabetically sorted actions reference

3.1. Process management and security
------------------------------------

global-one

3.4. Userlists
--------------

3.4 placeholder

4.1. Proxy keywords matrix
--------------------------

 keyword                              defaults   frontend   listen    backend
------------------------------------+----------+----------+---------+---------
maxconn                                   X          X         X         X
------------------------------------+----------+----------+---------+---------

4.2. Alphabetically sorted keywords reference
---------------------------------------------

maxconn <value>
  Description.

4.3. Actions keywords matrix
----------------------------

 keyword                QUIC: Ini   TCP: RqCon RqSes RqCnt RsCnt   HTTP: Req Res Aft
----------------------+-----------+-----------+-----+-----+------+----------+---+----
set-var                        -           X     X     X     X            X   X   X

4.4. Alphabetically sorted actions reference
--------------------------------------------

set-var <var-name> <expr>
  Usable in:  QUIC Ini|    TCP RqCon| RqSes| RqCnt| RsCnt|    HTTP Req| Res| Aft
                    - |          X  |   X  |   X  |   X  |          X |  X |  -

  Sets a variable.
"""
    path = tmp_path / "configuration.txt"
    path.write_text(content, encoding="utf-8")
    result = parse_configuration(path)
    assert "set-var" in result.action_reference
    assert "http-request" in result.action_reference["set-var"].rulesets
    assert "set-var" in result.action_matrix["http_request_actions"]
    assert "set-var" in result.action_matrix["tcp_request_actions"]
