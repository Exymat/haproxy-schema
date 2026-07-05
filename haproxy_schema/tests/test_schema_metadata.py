from __future__ import annotations

from haproxy_schema.schema import HaproxySchema
from haproxy_schema.schema_metadata import apply_schema_metadata, load_schema_metadata


def test_load_bundled_schema_metadata_resolves_refs() -> None:
    metadata = load_schema_metadata("3.4")
    assert metadata["address_policies"]["server"]["portOffset"] is True
    assert metadata["semantic_groups"]["line_option_group_for_kind"]["bind"] == "bind_options"


def test_apply_schema_metadata_round_trip() -> None:
    schema = HaproxySchema(version="test")
    metadata = load_schema_metadata("2.6")
    apply_schema_metadata(schema, metadata)
    data = schema.to_json_dict()
    reloaded = HaproxySchema.from_json_dict(data)
    assert reloaded.address_policies["tcpCheckAddr"]["portOk"] is True
    assert reloaded.sample_casts[0][0] is True
    assert reloaded.validation_rules["special_argument_rules"]["cookie"]["modes"]
