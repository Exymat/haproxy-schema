from haproxy_schema.slot_model import layout_from_signature, pick_best_layout


def test_server_layout_from_signature() -> None:
    layout = layout_from_signature("server", "server <name> <address>[:[port]] [param*]")
    assert layout is not None
    assert len(layout.fixed_slots) == 2
    assert layout.fixed_slots[0].role == "name"
    assert layout.fixed_slots[1].role == "address"
    assert layout.fixed_slots[1].port == "optional"
    assert layout.nested_start_index == 3


def test_bind_layout_from_signature() -> None:
    layout = pick_best_layout(
        "bind",
        [
            "bind /<path> [, ...] [param*]",
            "bind [<address>]:<port_range> [, ...] [param*]",
        ],
    )
    assert layout is not None
    assert layout.fixed_slots[0].role == "address"
    assert layout.nested_start_index == 2
