"""Verify the shared metadata contract and deterministic TypeScript generation."""
import json
import sys
from pathlib import Path
from typing import Literal, NotRequired, get_args, get_origin, get_type_hints, is_typeddict

import pytest

from haproxy_schema import metadata_contract as contract
from haproxy_schema.typescript_contract import main, render, typescript_type
from ._paths import haproxy_vscode_root


def test_type_mapping():
    assert typescript_type(str) == "string"
    assert typescript_type(int) == "number"
    assert typescript_type(bool) == "boolean"
    assert typescript_type(Literal["name", "path"]) == '"name" | "path"'
    assert typescript_type(NotRequired[int]) == "number"
    assert typescript_type(list[str]) == "Array<string>"
    assert typescript_type(dict[str, list[int]]) == "Record<string, Array<number>>"
    assert typescript_type(contract.FetchReference) == "FetchReference"
    with pytest.raises(TypeError, match="Unsupported contract"):
        typescript_type(float)
    with pytest.raises(TypeError, match="Unsupported contract"):
        typescript_type(dict[int, str])


def test_generate_and_check(tmp_path, monkeypatch, capsys):
    target = tmp_path / "metadata.generated.ts"
    monkeypatch.setattr(sys, "argv", ["contract", "--out", str(target)])
    main()
    assert target.read_text() == render()
    assert "argument_index?: number" in render()
    assert "converter_min_args?: Record<string, number>" in render()
    monkeypatch.setattr(sys, "argv", ["contract", "--out", str(target), "--check"])
    main()
    target.write_text("stale")
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 1
    assert "stale" in capsys.readouterr().err
    target.unlink()
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 1


def test_committed_types_are_current():
    path = haproxy_vscode_root() / "src/schema/metadata.generated.ts"
    if not path.exists():
        pytest.skip("extension checkout unavailable")
    assert path.read_text(encoding="utf-8") == render()


def _assert_shape(value, annotation, path):
    """Validate actual generated metadata against annotations, including nested records."""
    origin = get_origin(annotation)
    args = get_args(annotation)
    if is_typeddict(annotation):
        assert isinstance(value, dict), path
        hints = get_type_hints(annotation)
        assert value.keys() <= hints.keys(), path
        assert annotation.__required_keys__ <= value.keys(), path
        for key, item in value.items():
            _assert_shape(item, hints[key], f"{path}.{key}")
    elif origin is dict:
        assert isinstance(value, dict), path
        for key, item in value.items():
            assert isinstance(key, str), path
            _assert_shape(item, args[1], f"{path}.{key}")
    elif origin is list:
        assert isinstance(value, list), path
        for index, item in enumerate(value):
            _assert_shape(item, args[0], f"{path}.{index}")
    elif origin is Literal:
        assert value in args, path
    else:
        assert type(value) is annotation, path


@pytest.mark.parametrize("path", sorted((haproxy_vscode_root() / "schemas").glob("*.schema.json")))
def test_generated_metadata_matches_contract(path: Path):
    schema = json.loads(path.read_text(encoding="utf-8"))
    for key, model in [("symbols", contract.SchemaSymbols),
                       ("semantic_groups", contract.SchemaSemanticGroups),
                       ("validation_rules", contract.SchemaValidationRules)]:
        _assert_shape(schema[key], model, f"{path.name}.{key}")
    for keyword in schema["keywords"].values():
        for variant in [keyword, *keyword.get("variants", [])]:
            for slot in (variant.get("argument_model") or {}).get("slots", []):
                _assert_shape(slot, contract.ArgumentSlot, f"{path.name}.{keyword['name']}.slot")
