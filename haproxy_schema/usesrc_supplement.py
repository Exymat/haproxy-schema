"""Fill usesrc server-line metadata omitted from standalone doc sections."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .schema import HaproxySchema

USESRC_SERVER_SIGNATURES = (
    "usesrc <addr2>[:<port2>]",
    "usesrc client|clientip",
    "usesrc hdr_ip(<hdr>[,<occ>])",
)


def supplement_usesrc_metadata(
    schema: HaproxySchema,
    server_signature_map: dict[str, list[str]],
) -> None:
    """Synthesize usesrc signatures from the source/usesrc doc forms and dkall inventory."""
    kw = schema.keywords.get("usesrc")
    if kw is None:
        return

    signatures = list(USESRC_SERVER_SIGNATURES)
    kw.signatures = signatures
    server_signature_map["usesrc"] = signatures

    for semantic in kw.line_option_semantics:
        if semantic.parent_kind == "server":
            semantic.takes_value = True
