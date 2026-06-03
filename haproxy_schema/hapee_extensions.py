"""HAPEE Enterprise keywords absent from open-source HAProxy configuration.txt."""

from __future__ import annotations

# Section name -> directive keywords (without argument values).
HAPEE_SECTION_KEYWORDS: dict[str, tuple[str, ...]] = {
    "global": (
        "module-path",
        "module-load",
        "saml-sso-load",
    ),
}
