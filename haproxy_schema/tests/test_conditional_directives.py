from haproxy_schema.config_validator import _tokenize_line


def test_tokenize_conditional_if_line() -> None:
    tokens = _tokenize_line(".if defined(HAPROXY_MWORKER)")
    assert [t.text for t in tokens] == [".if", "defined(HAPROXY_MWORKER)"]


def test_tokenize_status_notice_line() -> None:
    tokens = _tokenize_line('.notice "SSL support is mandatory"')
    assert tokens[0].text == ".notice"
    assert tokens[1].text == '"SSL support is mandatory"'


def test_tokenize_if_with_trailing_comment() -> None:
    tokens = _tokenize_line(".if streq(0, 1)  # example")
    assert tokens[0].text == ".if"
    assert "streq" in tokens[1].text
