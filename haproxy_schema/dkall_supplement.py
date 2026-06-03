from __future__ import annotations

from pathlib import Path

from .dkall_parser import DkallParseResult, parse_dkall


def supplement_missing_tls_options(dkall: DkallParseResult, package_dir: Path) -> None:
    """Fill bind/server TLS keywords omitted when -dKall comes from a no-SSL build."""
    if "ssl" in dkall.server_options and "ssl" in dkall.bind_options:
        return

    for name in ("dkall-3.2.txt", "dkall-3.0.txt"):
        ref_path = package_dir / name
        if not ref_path.is_file():
            continue
        ref = parse_dkall(ref_path)
        if "ssl" not in ref.server_options and "ssl" not in ref.bind_options:
            continue
        dkall.bind_options |= ref.bind_options - dkall.bind_options
        dkall.server_options |= ref.server_options - dkall.server_options
        return
