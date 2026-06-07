from haproxy_schema.signature_model import build_argument_model, parse_signature_model


def test_mode_single_enum_argument() -> None:
    model = build_argument_model("mode", ["mode { tcp|http|log }"])
    assert model is not None
    assert model.min_args == 1
    assert model.max_args == 1
    assert set(model.slots[0].enum) == {"http", "log", "tcp"}


def test_daemon_zero_arguments() -> None:
    model = parse_signature_model("daemon", "daemon")
    assert model is not None
    assert model.min_args == 0
    assert model.max_args == 0
    assert model.slots == []


def test_maxconn_one_placeholder() -> None:
    model = build_argument_model("maxconn", ["maxconn <number>", "maxconn <conns>"])
    assert model is not None
    assert model.min_args == 1
    assert model.max_args == 1


def test_bind_is_variadic() -> None:
    model = build_argument_model("bind", ["bind <addr> [param*]"])
    assert model is not None
    assert model.max_args is None
    assert any(slot.variadic for slot in model.slots)


def test_optional_enum_slot() -> None:
    model = parse_signature_model("http-reuse { never | safe | aggressive | always }", "http-reuse")
    assert model is not None
    assert model.max_args == 1
    assert "never" in model.slots[0].enum


def test_trailing_ellipsis_makes_variadic() -> None:
    model = build_argument_model(
        "ssl-default-bind-options",
        ["ssl-default-bind-options [<option>]..."],
    )
    assert model is not None
    assert model.max_args is None
    assert model.slots[-1].variadic


def test_compression_algo_variadic() -> None:
    model = build_argument_model("compression algo", ["compression algo <algorithm> ..."])
    assert model is not None
    assert model.max_args is None


def test_trace_args_ellipsis() -> None:
    model = build_argument_model("trace", ["trace <source> <args...>"])
    assert model is not None
    assert model.max_args is None


def test_optional_literal_in_brackets_becomes_enum() -> None:
    model = build_argument_model(
        "balance url_param",
        ["balance url_param <param> [check_post]"],
    )
    assert model is not None
    assert model.min_args == 1
    assert model.max_args == 2
    assert model.slots[1].optional is True
    assert model.slots[1].enum == ["check_post"]


def test_doc_enum_enrichment_does_not_pollute_trailing_literal_enum() -> None:
    model = parse_signature_model("balance url_param <param> [check_post]", "balance url_param")
    assert model is not None
    # Simulate attach_argument_models enrichment behavior.
    from haproxy_schema.signature_model import _enrich_slots_from_doc_enums

    _enrich_slots_from_doc_enums(model, ["roundrobin", "leastconn"])
    assert model.slots[0].enum == []
    assert model.slots[1].enum == ["check_post"]


def test_server_signature_keeps_name_and_address_slots() -> None:
    model = build_argument_model(
        "server",
        [
            "server <name> <address>[:[port]] [param*]",
            "server <name> <address> [param*]",
        ],
    )
    assert model is not None
    assert model.min_args >= 2
    assert model.slots[0].value_kind == "name"
    assert model.slots[1].value_kind == "address"


def test_bind_optional_address_is_still_address_kind() -> None:
    model = build_argument_model("bind", ["bind [<address>]:<port_range> [, ...] [param*]"])
    assert model is not None
    assert model.slots[0].value_kind == "address"


def test_optional_group_with_literal_and_placeholder_does_not_leak_signature_syntax() -> None:
    model = build_argument_model(
        "option forwardfor",
        ["option forwardfor [ except <network> ] [ header <name> ] [ if-none ]"],
    )
    assert model is not None
    all_enums = [value for slot in model.slots for value in slot.enum]
    assert all("<" not in value and "[" not in value and "]" not in value for value in all_enums)


def test_keyword_suffix_parenthesized_argument_is_parsed() -> None:
    model = build_argument_model("persist rdp-cookie", ["persist rdp-cookie(<name>)"])
    assert model is not None
    assert model.min_args == 1
    assert model.slots[0].value_kind == "name"
