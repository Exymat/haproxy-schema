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
