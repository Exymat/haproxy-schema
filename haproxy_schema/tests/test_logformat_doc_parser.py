from pathlib import Path

from haproxy_schema.logformat_doc_parser import parse_logformat_reference

from ._paths import haproxy_configuration_txt


def test_parse_logformat_reference_from_configuration_txt() -> None:
    path = haproxy_configuration_txt("3.4")
    if not path.is_file():
        return

    ref = parse_logformat_reference(path)

    assert "Q" in ref.flags
    assert "E" in ref.flags
    assert "json" in ref.flags
    assert "%ci" in ref.aliases
    assert "%OG" in ref.aliases
    assert ref.aliases["%ci"].type == "IP"
    assert ref.aliases["%ci"].sample_fetch.startswith("%[")
    assert ref.aliases["%r"].restrictions == "H"


def test_parse_logformat_reference_fixture() -> None:
    path = Path(__file__).with_name("_tmp_logformat_reference_configuration.txt")
    path.write_text(
        "\n".join(
            [
                "8.2.6. Custom log format",
                "------------------------",
                "",
                "Supported item flags are (may be enabled/disabled from item's arguments):",
                "  * Q: quote a string",
                "  * E: escape characters",
                "",
                "  Example:",
                "    log-format %{+Q}o",
                "",
                "Please refer to the table below for currently defined aliases :",
                "",
                "  +---+------+-----------------------------------------------+---------+",
                "  | R | alias| field name                                    | type    |",
                "  +===+======+===============================================+=========+",
                "  |   | %o   | special, apply flags on all following items   |         |",
                "  +---+------+-----------------------------------------------+---------+",
                "  |   | %ci  | client_ip                                     |         |",
                "  |   |      | %[src]                                        | IP      |",
                "  +---+------+-----------------------------------------------+---------+",
                "  | H | %r   | http_request                                  | string  |",
                "  +---+------+-----------------------------------------------+---------+",
                "",
                "    R = Restrictions : H = mode http only",
                "",
                "8.3. Advanced logging options",
                "-----------------------------",
            ]
        ),
        encoding="utf-8",
    )
    try:
        ref = parse_logformat_reference(path)
    finally:
        path.unlink(missing_ok=True)

    assert ref.flags["Q"] == "quote a string"
    assert ref.aliases["%ci"].sample_fetch == "%[src]"
    assert ref.aliases["%ci"].type == "IP"
    assert ref.aliases["%r"].restrictions == "H"
