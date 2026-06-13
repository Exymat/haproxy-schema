from haproxy_schema.language_data import build_from_paths

from ._paths import dkall_dump, haproxy_configuration_txt


def test_build_language_data_mode_description() -> None:
    doc = haproxy_configuration_txt("3.0")
    dkall = dkall_dump("3.0")
    if not doc.is_file() or not dkall.is_file():
        return

    data = build_from_paths(doc, dkall, "3.0")
    mode = data.keywords.get("mode")
    assert mode is not None
    assert mode.description
    assert "http" in " ".join(mode.signatures).lower() or mode.signatures
    assert data.groups["http_request_actions"]

    bind = data.keywords.get("bind")
    assert bind is not None
    assert "global" not in bind.sections
    assert "frontend" in bind.sections
    assert "listen" in bind.sections
    assert bind.variants
    proxy_variant = next(v for v in bind.variants if v.chapter == "4.2")
    peers_variant = next(v for v in bind.variants if "peers" in v.sections)
    assert "listening" in proxy_variant.description.lower()
    assert "peer" in peers_variant.description.lower()


def test_build_language_data_preserves_distinct_acl_flags() -> None:
    doc = haproxy_configuration_txt("3.4")
    dkall = dkall_dump("3.4")
    if not doc.is_file() or not dkall.is_file():
        return

    data = build_from_paths(doc, dkall, "3.4")
    flags = {item.name: item for item in data.groups["acl_flags"]}

    assert flags["-m"].description == "use a specific pattern matching method"
    assert flags["-m"].signature == "-m"
    assert flags["-M"].description == "load the file pointed by -f like a map."
    assert flags["-M"].signature == "-M"
    assert flags["--"].signature == "--"
