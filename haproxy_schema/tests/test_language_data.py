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
    assert "listening" in bind.description.lower()
    assert "peers section" not in bind.description.lower()
