from haproxy_schema.argument_docs import extract_argument_docs

from ._paths import haproxy_configuration_txt


def test_balance_argument_values_extracted() -> None:
    content = haproxy_configuration_txt("3.0")
    if not content.is_file():
        return

    lines = content.read_text(encoding="utf-8").splitlines()
    idx = next(i for i, line in enumerate(lines) if line.strip() == "balance <algorithm> [ <arguments> ]")
    params = extract_argument_docs(lines, idx)
    assert params
    algorithm = next((p for p in params if p.parameter == "<algorithm>"), None)
    assert algorithm is not None
    names = {value.name for value in algorithm.values}
    assert "roundrobin" in names
    assert "static-rr" in names
    assert "url_param" in names
    assert "random" in names
    assert "hdr(<name>)" in names
    assert "rdp-cookie" in names
    roundrobin = next(v for v in algorithm.values if v.name == "roundrobin")
    assert "turns" in roundrobin.description.lower()


def test_mode_enum_from_arguments_section() -> None:
    lines = """mode { tcp|http|log }
  Set the running mode.

  Arguments :
    tcp       TCP mode description.
    http      HTTP mode description.
""".splitlines()
    params = extract_argument_docs(lines, 0)
    values = {value.name for param in params for value in param.values}
    assert "tcp" in values
    assert "http" in values
