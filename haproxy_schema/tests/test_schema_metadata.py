from __future__ import annotations

from pathlib import Path

import pytest

from haproxy_schema.doc_parser import parse_configuration
from haproxy_schema.dkall_parser import parse_dkall
from haproxy_schema.merge import merge_schema
from haproxy_schema.metadata_builder import _derive_balance_variant_algorithms, build_schema_metadata
from haproxy_schema.schema import HaproxySchema
from haproxy_schema.schema_metadata import iter_curated_entries, load_curated_metadata
from haproxy_schema.source_metadata_extractors import (
    extract_address_policies,
    extract_cookie_modes,
    extract_http_send_name_header_rule,
    extract_log_address_skip,
    extract_mysql_check_rule,
    extract_sample_casts,
    extract_sample_fetch_references,
    extract_sample_min_args,
    extract_sample_types,
)

from ._paths import SUPPORTED_VERSIONS, dkall_dump, haproxy_configuration_txt, monorepo_root


def _fixture_root(tmp_path: Path) -> Path:
    root = tmp_path / "haproxy"
    (root / "src").mkdir(parents=True)
    (root / "src" / "sample.c").write_text(
        """
const char *smp_to_type[SMP_TYPES] = {
    [SMP_T_ANY]  = "any",
    [SMP_T_STR]  = "str",
};
sample_cast_fct sample_casts[SMP_TYPES][SMP_TYPES] = {
/* from: ANY */ { c_none, c_pseudo },
/*        STR */ { NULL,   c_none   }
};
{ "ipmask", sample_conv_ipmask, ARG2(1,MSK4,MSK6), NULL, SMP_T_ADDR, SMP_T_ADDR },
""",
        encoding="utf-8",
    )
    (root / "src" / "cfgparse.c").write_text(
        """
int str2listener(void) {
  sk = str2sa_range(str, NULL, &port, &end, &fd, &proto, NULL, err,
                    NULL, NULL, NULL, PA_O_PORT_OK | PA_O_PORT_MAND | PA_O_PORT_RANGE);
}
""",
        encoding="utf-8",
    )
    (root / "src" / "log.c").write_text(
        """
int parse_logger(char **args, void *loggers) {
  if (*(args[1]) && *(args[2]) == 0 && strcmp(args[1], "global") == 0) {}
  if (strcmp(args[1], "stdout") == 0) {}
  else if (strcmp(args[1], "stderr") == 0) {}
}
/* parse the target address */
sk = str2sa_range(raw, NULL, &port1, &port2, &fd, &proto, NULL,
                  err, NULL, NULL, NULL, PA_O_PORT_OK);
""",
        encoding="utf-8",
    )
    (root / "src" / "cfgparse-listen.c").write_text(
        """
else if (strcmp(args[0], "cookie") == 0) {
  if (strcmp(args[cur_arg], "rewrite") == 0) {}
  else if (strcmp(args[cur_arg], "secure") == 0) {}
}/* end else if */
else if (strcmp(args[0], "source") == 0) {
  /* "source", "usesrc", "interface" */
  sk = str2sa_range(args[1], NULL, &port1, &port2, NULL, NULL, NULL,
                    &errmsg, NULL, NULL, NULL, PA_O_PORT_OK);
}
else if (strcmp(args[0], "http-send-name-header") == 0) {
  if (strcasecmp(args[1], "host") == 0 ||
      strcasecmp(args[1], "connection") == 0) {}
}
else if (strcmp(args[0], "block") == 0) {}
""",
        encoding="utf-8",
    )
    (root / "src" / "server.c").write_text(
        """
/* Parse the "source" server keyword */
sk = str2sa_range(args[*cur_arg + 1], NULL, &port_low, &port_high, NULL, NULL, NULL,
                  &errmsg, NULL, NULL, NULL, PA_O_PORT_OK | PA_O_PORT_RANGE);
if (strcmp(args[*cur_arg + 1], "clientip") == 0) {}
sk = str2sa_range(args[*cur_arg + 1], NULL, &port1, &port2, NULL, NULL, NULL,
                  &errmsg, NULL, NULL, NULL, PA_O_PORT_OK);
/* Parse the "socks4" server keyword */
sk = str2sa_range(args[*cur_arg + 1], NULL, &port_low, &port_high, NULL, NULL, NULL,
                  &errmsg, NULL, NULL, NULL, PA_O_PORT_OK | PA_O_PORT_MAND);
/* several ways to check the port component */
sk = str2sa_range(args[*cur_arg], &port, &port1, &port2, NULL, NULL, &newsrv->addr_type,
                  &errmsg, NULL, &fqdn, &alt_proto, PA_O_PORT_OK | PA_O_PORT_OFS);
""",
        encoding="utf-8",
    )
    (root / "src" / "tcpcheck.c").write_text(
        """
int proxy_parse_mysql_check_opt(void) {
  if (strcmp(args[cur_arg], "user") != 0) {}
  if (strcmp(args[cur_arg+2], "post-41") == 0) {}
  else if (strcmp(args[cur_arg+2], "pre-41") == 0) {}
}
/* Parses the "option httpchk" */
else if (strcmp(args[cur_arg], "addr") == 0) {
  sk = str2sa_range(args[cur_arg+1], NULL, &port1, &port2, NULL, NULL, NULL,
                    errmsg, NULL, NULL, NULL, PA_O_PORT_OK);
}
{ "payload_lv", smp_fetch_payload_lv, ARG3(2,SINT,SINT,STR), NULL, SMP_T_BIN },
""",
        encoding="utf-8",
    )
    (root / "src" / "payload.c").write_text(
        '{ "payload_lv", smp_fetch_payload_lv, ARG3(2,SINT,SINT,STR), NULL, SMP_T_BIN },',
        encoding="utf-8",
    )
    (root / "src" / "map.c").write_text(
        '{ "map_str", sample_conv_map, ARG2(1,STR,STR), sample_load_map, SMP_T_STR, SMP_T_STR },',
        encoding="utf-8",
    )
    (root / "src" / "http_fetch.c").write_text(
        """
{ "http_auth",       smp_fetch_http_auth,     ARG1(1,USR), NULL, SMP_T_BOOL, SMP_USE_HRQHV },
{ "http_auth_group", smp_fetch_http_auth_grp, ARG1(1,USR), NULL, SMP_T_STR,  SMP_USE_HRQHV },
""",
        encoding="utf-8",
    )
    return root


def test_source_extractors_parse_c_fixtures(tmp_path: Path) -> None:
    root = _fixture_root(tmp_path)
    assert extract_sample_types(root)[0] == ["any", "str"]
    assert extract_sample_casts(root)[0] == [[True, True], [False, True]]
    policies = extract_address_policies(root)[0]
    assert policies["bind"] == {
        "portOk": True,
        "portMandatory": True,
        "portRange": True,
        "portOffset": False,
    }
    assert policies["server"]["portOffset"] is True
    assert policies["serverSocks4"]["portMandatory"] is True
    assert extract_cookie_modes(root)[0] == ["rewrite", "secure"]
    assert extract_mysql_check_rule(root)[0] == {
        "values": ["post-41", "pre-41", "user"],
        "modes": ["post-41", "pre-41"],
    }
    assert extract_http_send_name_header_rule(root, "3.4")[0] == {
        "forbidden_first_arg_by_min_version": {"3.4": ["connection", "host"]}
    }
    assert extract_log_address_skip(root)[0] == ["global", "stdout", "stderr"]
    assert extract_sample_fetch_references(root)[0] == {
        "http_auth": {"reference_kind": "userlist", "argument_index": 0, "scope": "global"},
        "http_auth_group": {"reference_kind": "userlist", "argument_index": 0, "scope": "global"},
    }
    fetch_min, converter_min, _ = extract_sample_min_args(root)
    assert fetch_min["payload_lv"] == 2
    assert converter_min["ipmask"] == 1
    assert converter_min["map_str"] == 1


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_balance_url_param_accepts_legacy_max_wait_example(version: str) -> None:
    mono = monorepo_root()
    if mono is None:
        pytest.skip("missing monorepo HAProxy source checkouts")
    doc_path = haproxy_configuration_txt(version)
    dkall_path = dkall_dump(version)
    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    schema = merge_schema(version, doc, dkall, dkall_package_dir=dkall_path.parent)
    variant = schema.keywords["balance url_param"]
    model = variant.argument_model
    assert model is not None
    assert model.max_args is None
    assert len(model.slots) == 3
    assert model.slots[2]["variadic"] is True


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_derive_balance_variant_algorithms(version: str) -> None:
    mono = monorepo_root()
    if mono is None:
        pytest.skip("missing monorepo HAProxy source checkouts")
    doc_path = haproxy_configuration_txt(version)
    dkall_path = dkall_dump(version)
    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    schema = merge_schema(version, doc, dkall, dkall_package_dir=dkall_path.parent)
    variants = _derive_balance_variant_algorithms(schema)
    assert variants == {"url_param": "balance url_param"}


def test_curated_metadata_requires_provenance_and_acceptance() -> None:
    curated = load_curated_metadata("3.4")
    entries = iter_curated_entries(curated)
    assert entries
    runtime = [entry for entry in entries if entry[1] == "curated_runtime"]
    assert all(entry[3] and entry[4] for entry in runtime)


@pytest.mark.parametrize("version", SUPPORTED_VERSIONS)
def test_generated_metadata_has_provenance_for_every_supported_version(version: str) -> None:
    mono = monorepo_root()
    if mono is None:
        pytest.skip("missing monorepo HAProxy source checkouts")
    doc_path = haproxy_configuration_txt(version)
    dkall_path = dkall_dump(version)
    doc = parse_configuration(doc_path)
    dkall = parse_dkall(dkall_path)
    schema = merge_schema(version, doc, dkall, dkall_package_dir=dkall_path.parent)
    report = getattr(schema, "_metadata_provenance_report")
    assert report["ok"] is True
    assert report["missing_required_fields"] == []
    assert report["provenance"]["sample_types"]["origin"] == "extracted"
    assert report["provenance"]["sample_casts"]["origin"] == "extracted"
    assert report["provenance"]["symbols.sample_fetch_references"]["http_auth"]["origin"] == "extracted"
    assert report["provenance"]["validation_rules.log_address_skip"]["origin"] == "extracted"
    assert "symbols.sample_fetch_references" not in report["curated_runtime"]
    assert "validation_rules.log_address_skip" not in report["curated_runtime"]
    assert "validation_rules.special_argument_rules.balance" not in report["curated_runtime"]
    assert (
        schema.validation_rules["special_argument_rules"]["balance"]["variant_algorithms"]["url_param"]
        == "balance url_param"
    )
    assert schema.address_policies["bind"]["portMandatory"] is True
    assert schema.sample_types
    assert len(schema.sample_casts) == len(schema.sample_types)
    assert schema.symbols["proxy_sections"] == ["frontend", "backend", "listen"]
    assert "completion_kind_to_action_group" in schema.semantic_groups
    assert schema.validation_rules["special_argument_rules"]["cookie"]["modes"]


def test_schema_metadata_round_trip(tmp_path: Path) -> None:
    schema = HaproxySchema(version="test")
    build = build_schema_metadata("2.6", _fixture_root(tmp_path), schema)
    schema.address_policies = build.metadata.get("address_policies", {})
    schema.sample_types = build.metadata.get("sample_types", [])
    schema.sample_casts = build.metadata.get("sample_casts", [])
    data = schema.to_json_dict()
    reloaded = HaproxySchema.from_json_dict(data)
    assert reloaded.sample_casts[0][0] is True
