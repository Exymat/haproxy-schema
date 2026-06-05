from pathlib import Path

from haproxy_schema.doc_parser import parse_configuration


def test_parse_configuration_extracts_sections_matrix_and_signatures(tmp_path: Path) -> None:
    content = """Summary
3.1.      Process management and security
4.1.      Proxy keywords matrix

3.1. Process management and security
------------------------------------

global-one <value>
  Description.

global-two
  Description.

3.4. Userlists
--------------

peers-only-keyword
  Peers section description.

bind [<address>]:port [param*]
  Peers bind description.

4.1. Proxy keywords matrix
--------------------------

 keyword                              defaults   frontend   listen    backend
------------------------------------+----------+----------+---------+---------
acl                                       X (!)      X         X         X
bind                                      -          X         X         -
capture request header                    -          X         X         -
maxconn                                   X          X         X         -
option forwardfor                         X          X         X         X
option redispatch                    (*)  X          -         X         X
option mysql-check                        X          -         X         X
------------------------------------+----------+----------+---------+---------

4.2. Alphabetically sorted keywords reference
---------------------------------------------

acl <aclname> <criterion> [flags]
  Description.

bind <addr> [param*]
  Description.

capture request header <len> <name>
  Description.

maxconn <value>
  Description.

  May be used in sections :   defaults | frontend | listen | backend
                                 yes   |    yes   |   yes  |   yes

option mysql-check
  Description.

  May be used in sections :   defaults | frontend | listen | backend
                                 -     |    -     |   yes  |   -
"""
    file_path = tmp_path / "configuration.txt"
    file_path.write_text(content, encoding="utf-8")

    result = parse_configuration(file_path)

    assert "global-one" in result.global_keywords
    assert "global-two" in result.global_keywords
    assert "maxconn" in result.matrix_keywords["defaults"]
    assert "option mysql-check" in result.matrix_keywords["listen"]
    assert "option redispatch" not in result.proxy_keywords
    assert "bind" in result.matrix_keywords["frontend"]
    assert "bind" not in result.matrix_keywords["backend"]
    assert "capture request header" in result.matrix_keywords["listen"]
    assert "acl <aclname> <criterion> [flags]" in result.signatures["acl"]
    assert "acl" in result.named_defaults_keywords
    assert "maxconn" not in result.named_defaults_keywords
    assert "bind <addr> [param*]" in result.signatures["bind"]
    assert result.keyword_docs["bind"].sections == ["frontend", "listen"]
    assert "global" not in result.keyword_docs["bind"].sections
    assert result.keyword_docs["bind"].description == "Description."
    assert result.keyword_docs["acl"].description == "Description."
    assert result.keyword_docs["global-one"].description == "Description."
    assert "peers-only-keyword" not in result.global_keywords


def test_parse_configuration_uses_doc_block_sections_when_missing_from_matrix(tmp_path: Path) -> None:
    content = """Summary
3.1.      Process management and security
4.1.      Proxy keywords matrix

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
stats uri                                 X          X         X         X
------------------------------------+----------+----------+---------+---------

4.2. Alphabetically sorted keywords reference
---------------------------------------------

stats show-modules
  Enable display of extra statistics module on the statistics page

  May be used in the following contexts: http

  May be used in sections :   defaults | frontend | listen | backend
                                 yes   |    yes   |   yes  |   yes

  Arguments : none

  New columns are added at the end of the line.
"""
    file_path = tmp_path / "configuration.txt"
    file_path.write_text(content, encoding="utf-8")

    result = parse_configuration(file_path)

    assert result.keyword_docs["stats show-modules"].sections == [
        "defaults",
        "frontend",
        "listen",
        "backend",
    ]
    assert "stats show-modules" in result.proxy_keywords
    assert "stats show-modules" in result.matrix_keywords["frontend"]


def test_parse_configuration_extracts_cache_section_keywords(tmp_path: Path) -> None:
    content = """Summary
6.2.1.        Cache section
6.2.2.        Proxy section

6.2.1. Cache section
--------------------

cache <name>
  Declare a cache section.

max-age <seconds>
  Maximum expiration duration.

max-object-size <bytes>
  Maximum cached object size.

process-vary <on/off>
  Enable Vary header processing.

total-max-size <megabytes>
  Cache size in RAM.

6.2.2. Proxy section
--------------------

The proxy section making use of the cache.
"""
    file_path = tmp_path / "configuration.txt"
    file_path.write_text(content, encoding="utf-8")

    # Minimal required sections for parse_configuration.
    base = """3.1. Process management and security
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
"""
    file_path.write_text(base + content, encoding="utf-8")

    result = parse_configuration(file_path)

    assert "total-max-size" in result.section_keywords["cache"]
    assert "max-object-size" in result.section_keywords["cache"]
    assert "max-age" in result.section_keywords["cache"]
    assert "process-vary" in result.section_keywords["cache"]
    assert "cache" not in result.section_keywords["cache"]
    assert result.keyword_docs["total-max-size"].sections == ["cache"]
    assert "add" not in result.section_keywords.get("cache", set())
    assert "xor" not in result.section_keywords.get("cache", set())


def test_parse_configuration_extracts_4_3_actions_matrix(tmp_path: Path) -> None:
    base = """3.1. Process management and security
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
accept                         X           X     X     X     X            -   -   -
set-var                        -           X     X     X     X            X   X   X
set-path                       -           -     -     -     -            X   -   -
track-sc0                      -           X     X     X     -            X   X   -

4.4. Alphabetically sorted actions reference
--------------------------------------------

set-var <var-name> <expr>
  Description.
"""
    file_path = tmp_path / "configuration.txt"
    file_path.write_text(base, encoding="utf-8")

    result = parse_configuration(file_path)

    assert "set-var" in result.action_matrix["http_request_actions"]
    assert "set-path" in result.action_matrix["http_request_actions"]
    assert "track-sc0" in result.action_matrix["http_request_actions"]
    assert "accept" in result.action_matrix["tcp_request_actions"]
    assert "accept" in result.action_matrix["quic_initial_actions"]
    assert "set-var" in result.action_matrix["http_response_actions"]
