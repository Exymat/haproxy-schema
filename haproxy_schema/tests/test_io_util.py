from __future__ import annotations

from pathlib import Path

from haproxy_schema.io_util import write_text_lf


def test_write_text_lf_uses_unix_newlines(tmp_path: Path) -> None:
    path = tmp_path / "out.json"
    write_text_lf(path, "{\n  \"a\": 1\n}\n")
    raw = path.read_bytes()
    assert b"\r\n" not in raw
    assert raw.endswith(b"\n")
