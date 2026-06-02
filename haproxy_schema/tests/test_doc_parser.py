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
"""
    file_path = tmp_path / "configuration.txt"
    file_path.write_text(content, encoding="utf-8")

    result = parse_configuration(file_path)

    assert "global-one" in result.global_keywords
    assert "global-two" in result.global_keywords
    assert "maxconn" in result.matrix_keywords["defaults"]
    assert "option mysql-check" in result.matrix_keywords["listen"]
    assert "option redispatch" in result.matrix_keywords["defaults"]
    assert "bind" in result.matrix_keywords["frontend"]
    assert "bind" not in result.matrix_keywords["backend"]
    assert "capture request header" in result.matrix_keywords["listen"]
    assert "acl <aclname> <criterion> [flags]" in result.signatures["acl"]
    assert "bind <addr> [param*]" in result.signatures["bind"]
    assert result.keyword_docs["bind"].sections == ["frontend", "listen"]
    assert "global" not in result.keyword_docs["bind"].sections
    assert result.keyword_docs["bind"].description == "Description."
    assert result.keyword_docs["acl"].description == "Description."
    assert result.keyword_docs["global-one"].description == "Description."
    assert "peers-only-keyword" not in result.global_keywords
