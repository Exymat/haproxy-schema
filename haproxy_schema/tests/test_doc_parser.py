from pathlib import Path

from haproxy_schema.doc_parser import parse_configuration

from ._paths import haproxy_configuration_txt


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


def test_parse_configuration_assigns_chapter_per_global_subsection(tmp_path: Path) -> None:
    content = """Summary
3.1.      Process management and security
3.2.      Performance tuning
3.4.      HTTPClient tuning
4.1.      Proxy keywords matrix

3.1. Process management and security
------------------------------------

chroot { <jail dir> | auto }
  Process management description.

3.2. Performance tuning
-----------------------

tune.vars.global-max-size <size>
  Performance tuning description.

3.4. HTTPClient tuning
----------------------

httpclient.retries <count>
  HTTPClient description.

4.1. Proxy keywords matrix
--------------------------

 keyword                              defaults   frontend   listen    backend
------------------------------------+----------+----------+---------+---------
------------------------------------+----------+----------+---------+---------

4.2. Alphabetically sorted keywords reference
---------------------------------------------

"""
    file_path = tmp_path / "configuration.txt"
    file_path.write_text(content, encoding="utf-8")

    result = parse_configuration(file_path)

    assert result.keyword_docs["chroot"].chapter == "3.1"
    assert result.keyword_docs["tune.vars.global-max-size"].chapter == "3.2"
    assert result.keyword_docs["httpclient.retries"].chapter == "3.4"
    assert "tune.vars.global-max-size" in result.global_keywords
    assert "httpclient.retries" not in result.global_keywords


def test_parse_configuration_assigns_legacy_httpclient_chapter(tmp_path: Path) -> None:
    content = """Summary
3.1.      Process management and security
3.4.      Userlists
3.5.      Peers
3.11.     HTTPClient tuning
4.1.      Proxy keywords matrix

3.1. Process management and security
------------------------------------

chroot { <jail dir> | auto }
  Process management description.

3.4. Userlists
--------------

3.5. Peers
----------

peers-only-keyword
  Peers section description.

3.11. HTTPClient tuning
-----------------------

httpclient.resolvers.disabled <on|off>
  Disable the DNS resolution of the httpclient.

4.1. Proxy keywords matrix
--------------------------

 keyword                              defaults   frontend   listen    backend
------------------------------------+----------+----------+---------+---------
------------------------------------+----------+----------+---------+---------

4.2. Alphabetically sorted keywords reference
---------------------------------------------

"""
    file_path = tmp_path / "configuration.txt"
    file_path.write_text(content, encoding="utf-8")

    result = parse_configuration(file_path)

    assert result.keyword_docs["httpclient.resolvers.disabled"].chapter == "3.11"
    assert "httpclient.resolvers.disabled <on|off>" in result.signatures["httpclient.resolvers.disabled"]
    assert "userlist placeholder" not in result.keyword_docs


def test_parse_configuration_extracts_legacy_log_forward_and_crt_store(tmp_path: Path) -> None:
    content = """Summary
3.1.      Process management and security
3.4.      Userlists
3.5.      Peers
3.6.      Mailers
3.10.     Log forwarding
3.12.     Certificate Storage
4.1.      Proxy keywords matrix

3.1. Process management and security
------------------------------------

global-one

3.4. Userlists
--------------

userlist <name>
  Declare a userlist section.

3.5. Peers
----------

peers-only-keyword
  Peers section placeholder.

3.6. Mailers
------------

mailers <mailersect>
  Declare a mailers section.

mailer <mailername> <ip>:<port>
  Define a mailer.

3.10. Log forwarding
--------------------

log-forward <name>
  Declare a log forwarding section.

dgram-bind <addr> [param*]
  Datagram listener.

3.12. Certificate Storage
-------------------------

load [crt <filename>] [param*]
  Load SSL files in the certificate storage.

crt-base <dir>
  Default certificate directory.

4.1. Proxy keywords matrix
--------------------------

 keyword                              defaults   frontend   listen    backend
------------------------------------+----------+----------+---------+---------
------------------------------------+----------+----------+---------+---------

4.2. Alphabetically sorted keywords reference
---------------------------------------------

"""
    file_path = tmp_path / "configuration.txt"
    file_path.write_text(content, encoding="utf-8")

    result = parse_configuration(file_path)

    assert "mailers" in result.keyword_docs
    assert "mailers <mailersect>" in result.signatures["mailers"]
    assert "mailer" in result.section_keywords["mailers"]
    assert "mailers" not in result.section_keywords["mailers"]

    assert "log-forward" in result.keyword_docs
    assert "dgram-bind" in result.keyword_docs
    assert result.keyword_docs["dgram-bind"].sections == ["log-forward"]

    assert "load" in result.keyword_docs
    assert result.keyword_docs["load"].sections == ["crt-store"]
    assert "crt-base" in result.section_keywords["crt-store"]


def test_parse_configuration_preserves_chapter_variants_for_bind(tmp_path: Path) -> None:
    content = """Summary
3.1.      Process management and security
3.4.      Userlists
3.5.      Peers
3.10.     Log forwarding
4.1.      Proxy keywords matrix

3.1. Process management and security
------------------------------------

global-one

3.4. Userlists
--------------

userlist <name>
  Declare a userlist section.

3.5. Peers
----------

bind [<address>]:port [param*]
  Defines the binding parameters of the local peer of this peers section.

3.10. Log forwarding
--------------------

bind <addr> [param*]
  Used to configure a stream log listener to receive messages to forward.

4.1. Proxy keywords matrix
--------------------------

 keyword                              defaults   frontend   listen    backend
------------------------------------+----------+----------+---------+---------
bind                                      -          X         X         -
------------------------------------+----------+----------+---------+---------

4.2. Alphabetically sorted keywords reference
---------------------------------------------

bind [<address>]:<port_range> [, ...] [param*]
  Define one or several listening addresses and/or ports in a frontend.

  May be used in sections :   defaults | frontend | listen | backend
                                 no   |    yes   |   yes  |   no
"""
    file_path = tmp_path / "configuration.txt"
    file_path.write_text(content, encoding="utf-8")

    result = parse_configuration(file_path)
    bind = result.keyword_docs["bind"]
    chapters = {variant.chapter for variant in bind.variants}
    assert "4.2" in chapters
    assert "3.5" in chapters
    assert "3.10" in chapters
    proxy = bind.variant_for("4.2")
    peers = bind.variant_for("3.5")
    log_forward = bind.variant_for("3.10")
    assert "frontend" in proxy.sections
    assert "peers" in peers.sections
    assert "log-forward" in log_forward.sections
    assert "frontend" in proxy.description.lower()
    assert "peer" in peers.description.lower()
    assert "log listener" in log_forward.description.lower()


def test_parse_configuration_maps_healthchecks_section_by_heading_title(tmp_path: Path) -> None:
    content = """Summary
3.1.      Process management and security
3.4.      Userlists
4.1.      Proxy keywords matrix
12.8.     ACME
12.9.     Healthchecks

3.1. Process management and security
------------------------------------

global-one

3.4. Userlists
--------------

userlist <name>
  Declare a userlist section.

4.1. Proxy keywords matrix
--------------------------

 keyword                              defaults   frontend   listen    backend
------------------------------------+----------+----------+---------+---------
bind                                      -          X         X         -
------------------------------------+----------+----------+---------+---------

4.2. Alphabetically sorted keywords reference
---------------------------------------------

bind [<address>]:<port_range> [, ...] [param*]
  Define one or several listening addresses and/or ports in a frontend.

12.8. ACME
----------

acme <name>
  Declare an ACME section.

12.9. Healthchecks
------------------

healthcheck <name>
  Created a new healthcheck with name <name>.

tcp-check connect [default] [port <expr>]
  Adds a tcp health-check connection rule.
"""
    file_path = tmp_path / "configuration.txt"
    file_path.write_text(content, encoding="utf-8")

    result = parse_configuration(file_path)

    assert "healthcheck" in result.keyword_docs
    assert "tcp-check connect" in result.section_keywords["healthcheck"]
    assert result.keyword_docs["healthcheck"].sections == ["healthcheck"]
    assert result.keyword_docs["tcp-check connect"].sections == ["healthcheck"]
    assert "program" not in result.section_keywords or "tcp-check connect" not in result.section_keywords["program"]


def test_parse_configuration_real_docs_cover_late_sections_and_healthchecks() -> None:
    doc34 = haproxy_configuration_txt("3.4")
    if not doc34.is_file():
        return

    result34 = parse_configuration(doc34)
    for section in (
        "peers",
        "traces",
        "userlist",
        "mailers",
        "http-errors",
        "ring",
        "log-forward",
        "crt-store",
        "crt-list",
        "acme",
        "healthcheck",
    ):
        assert section in result34.section_keywords
    assert "bind" in result34.section_keywords["peers"]
    assert "bind" in result34.section_keywords["log-forward"]
    assert "tcp-check connect" in result34.section_keywords["healthcheck"]
    assert result34.keyword_docs["healthcheck"].sections == ["healthcheck"]
    assert "program" not in result34.section_keywords

    bind34 = result34.keyword_docs["bind"]
    assert "peers" in bind34.variant_for("11.2").sections
    assert "log-forward" in bind34.variant_for("12.6").sections

    doc32 = haproxy_configuration_txt("3.2")
    if not doc32.is_file():
        return

    result32 = parse_configuration(doc32)
    assert "program" in result32.section_keywords
    assert "command" in result32.section_keywords["program"]
    assert "healthcheck" not in result32.section_keywords


def test_parse_configuration_extracts_filter_directive_keywords() -> None:
    doc30 = haproxy_configuration_txt("3.0")
    if not doc30.is_file():
        return

    result = parse_configuration(doc30)
    assert "filter cache" in result.proxy_keywords
    assert "filter cache" in result.keyword_docs
    cache_doc = result.keyword_docs["filter cache"]
    assert any("filter cache <name>" in sig for sig in cache_doc.signatures)
    assert cache_doc.description.strip()
    assert "frontend" in cache_doc.sections
    assert "backend" in cache_doc.sections
