from haproxy_schema.language_data import docs_anchor, docs_url


def test_docs_anchor_matches_dconv_rules() -> None:
    assert docs_anchor("mode", "4.2") == "4.2-mode"
    assert docs_anchor("option httplog", "4.2") == "4.2-option%20httplog"
    assert docs_anchor("req.hdr_cnt") == "req.hdr_cnt"
    assert docs_url("3.4", "req.hdr_cnt") == (
        "https://docs.haproxy.org/3.4/configuration.html#req.hdr_cnt"
    )


def test_docs_url_builds_configuration_link() -> None:
    assert docs_url("3.4", "tune.vars.global-max-size", "3.2") == (
        "https://docs.haproxy.org/3.4/configuration.html#3.2-tune.vars.global-max-size"
    )
