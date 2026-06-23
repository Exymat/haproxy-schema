from haproxy_schema.logformat_slots import collect_logformat_slots
from haproxy_schema.schema import ArgumentParamDoc, Keyword


def test_collect_logformat_slots_from_signatures_and_parameters() -> None:
    keywords = {
        "log-format": Keyword(
            name="log-format",
            signatures=["log-format <fmt>"],
        ),
        "set-var-fmt": Keyword(
            name="set-var-fmt",
            signatures=["set-var-fmt <var-name> <fmt>"],
        ),
        "http-check send": Keyword(
            name="http-check send",
            signatures=[
                "http-check send [meth <method>] [{ uri <uri> | uri-lf <fmt> }] [hdr <name> <fmt>]*"
            ],
            arguments=[
                ArgumentParamDoc(parameter="uri-lf <fmt>"),
                ArgumentParamDoc(parameter="hdr <name> <fmt>"),
            ],
        ),
    }

    slots = collect_logformat_slots(keywords)

    assert {"kind": "line_tail", "directive": "log-format", "skip": 0} in slots
    assert {"kind": "line_tail", "directive": "set-var-fmt", "skip": 1} in slots
    assert {"kind": "prefix", "prefix": "uri-lf", "skip": 0} in slots
    assert {"kind": "prefix", "prefix": "hdr", "skip": 1} in slots
    assert {"kind": "prefix", "prefix": "name-lf", "skip": 0} in slots
