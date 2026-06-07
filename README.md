# haproxy-schema

Python package that builds HAProxy **2.6**, **2.8**, **3.0**, **3.2**, and **3.4** schemas, language data, and TextMate grammars from `configuration.txt` and `haproxy -dKall` keyword dumps.

## What it produces

For each HAProxy release, the `build` command merges two upstream sources:

1. **`configuration.txt`** — section structure, keyword descriptions, argument shapes, ACL/sample references, and rule-action matrices.
2. **`haproxy -dKall`** — the complete keyword inventory emitted by a DEBUG-enabled binary.

## Relationship to haproxy-dconv

`haproxy-schema` **does reuse parts of haproxy-dconv parsing logic**, but it does so by
**vendoring selected rules into this repository** instead of importing `haproxy-dconv`
at runtime.

Upstream reference: [cbonte/haproxy-dconv](https://github.com/cbonte/haproxy-dconv)

- **What is reused:** keyword-line matching/parsing behavior aligned with dconv (see
  `haproxy_schema/dconv_bridge.py`).
- **Why not import dconv directly:** we want deterministic builds with no external
  runtime dependency, and we avoid Python module-name conflicts from dconv's historical
  `parser` package naming.
- **Practical effect:** schema generation still runs only from local `configuration.txt`
  and `dkall` inputs for each version, while keeping behavior compatible with dconv's
  keyword parsing model.

The CLI still exposes `--dconv-path` for compatibility, but this is currently
reserved because the active rules are vendored in-tree.

Outputs (written by **haproxy-vscode** `npm run generate:schema:<version>` or directly via the CLI):

| Artifact | Purpose |
| -------- | ------- |
| `haproxy-X.Y.schema.json` | Section/keyword model, statement rules, argument signatures, **`line_layout`** (prefix families, tcp phases, stats socket levels), **`options_with_value`**, enriched **`argument_model.slots.value_kind`**, **`fixed_slots.address_policy`**, sample **`max_args`** — drives diagnostics |
| `haproxy-X.Y.language.json` | Completion and hover payloads for the VS Code extension |
| `haproxy-X.Y.tmLanguage.json` | TextMate grammar for syntax highlighting |
| `coverage-X.Y.json` | Doc vs dkall gap report (keywords missing from either side) |

**2.6** and **2.8** use the legacy `configuration.txt` layout: rule actions are listed inline under each proxy keyword in §4.2 rather than in the separate §4.3/§4.4 reference used from 3.0 onward. The parser detects this automatically (`doc_layout.py`, `legacy_action_parser.py`).

## Repository layout

```
haproxy-schema/
  haproxy_schema/          # importable package (CLI: python -m haproxy_schema)
    dkall-2.6.txt          # checked-in -dKall dumps
    dkall-2.8.txt
    dkall-3.0.txt
    dkall-3.2.txt
    dkall-3.4.txt
    coverage-2.6.json      # doc vs dkall gap reports (written by build)
    coverage-2.8.json
    coverage-3.0.json
    coverage-3.2.json
    coverage-3.4.json
    tests/
  scripts/                 # dkall generation, optional binary install, test runner
```

Set `PYTHONPATH` to the **repository root** (the directory that contains `haproxy_schema/`), not the package directory itself.

## Quick start

```bash
cd haproxy-schema
export PYTHONPATH="$(pwd)"
python -m haproxy_schema build --help
python -m pytest haproxy_schema/tests -q
```

On Windows (PowerShell):

```powershell
cd haproxy-schema
$env:PYTHONPATH = (Get-Location).Path
python -m haproxy_schema build --help
python -m pytest haproxy_schema\tests -q
```

## CLI

| Command | Description |
| ------- | ----------- |
| `build` | Merge `configuration.txt` + dkall dump into schema JSON; optionally emit language data, grammar, and coverage report |
| `emit-grammar` | Regenerate a TextMate grammar from an existing schema JSON |
| `check-grammar` | Verify an emitted grammar covers all schema directives (prefix conflicts, missing cache keywords, stale hyphen forms) |
| `audit-docs` | Report bind/server/proxy options missing hover documentation |
| `doc-parse-audit` | Audit `configuration.txt` extraction quality for docs, signatures, hover payloads, and action references |
| `schema-fidelity-audit` | Audit how completely keyword arguments, nested options, sample functions, and value-taking options are modeled in schema JSON |

Example — build schema for 3.2 (paths assume sibling `haproxy_git/` trees):

```bash
python -m haproxy_schema build \
  --doc ../haproxy_git/haproxy-3.2/doc/configuration.txt \
  --dkall haproxy_schema/dkall-3.2.txt \
  --out /tmp/haproxy-3.2.schema.json \
  --language-data-out /tmp/haproxy-3.2.language.json \
  --grammar-out /tmp/haproxy-3.2.tmLanguage.json \
  --coverage-out haproxy_schema/coverage-3.2.json \
  --version 3.2

python -m haproxy_schema doc-parse-audit \
  --doc ../haproxy_git/haproxy-3.2/doc/configuration.txt \
  --dkall haproxy_schema/dkall-3.2.txt \
  --version 3.2 \
  --out haproxy_schema/doc-parse-audit-3.2.json

python -m haproxy_schema schema-fidelity-audit \
  --doc ../haproxy_git/haproxy-3.2/doc/configuration.txt \
  --dkall haproxy_schema/dkall-3.2.txt \
  --version 3.2 \
  --out haproxy_schema/schema-fidelity-audit-3.2.json
```

## Regenerate dkall dumps

Requires a DEBUG-enabled `haproxy` binary (Debian/Ubuntu packages usually work, or `scripts/install-haproxy-binary.sh`).

```bash
./scripts/generate-dkall.sh 2.6
./scripts/generate-dkall.sh 2.8
./scripts/generate-dkall.sh 3.0
./scripts/generate-dkall.sh 3.2
./scripts/generate-dkall.sh 3.4
```

On Windows, the same script runs inside WSL via `scripts/generate-dkall.ps1` (used by `npm run generate:dkall:*` in **haproxy-vscode**).

**HAProxy 3.4** must be built with OpenSSL so `server`/`bind` TLS keywords appear in the dkall dump (Debian packages for 3.0/3.2 are fine as-is):

```bash
./scripts/build-haproxy-3.4.sh   # USE_OPENSSL=1 → haproxy_schema/bin/haproxy-3.4
./scripts/generate-dkall.sh 3.4
```

For **2.6** and **2.8**, build or install matching binaries from `haproxy_git/haproxy-<version>/` (or use a system package of the correct release).

If a parent directory also contains `haproxy_git/haproxy-<version>/`, the script uses that tree’s `tests/conf/basic-check.cfg` when it produces a dump; otherwise it falls back to `/dev/null` (non-zero exit is normal). Version-specific binaries in `haproxy_schema/bin/haproxy-<ver>` are used when present (`install-haproxy-binary.sh` for 3.0/3.2; `build-haproxy-3.4.sh` for 3.4).

## VS Code extension

The **haproxy-vscode** extension consumes generated `schema.json`, `language.json`, and grammar files. Clone both repositories as siblings under the same parent directory:

```
parent/
  haproxy-schema/
  haproxy-vscode/
  haproxy_git/             # optional: haproxy-2.6/, haproxy-2.8/, haproxy-3.0/, … for doc + integration tests
```

Schema build and full test instructions live in [haproxy-vscode/README.md](../haproxy-vscode/README.md). From the parent directory:

```powershell
$env:PYTHONPATH = (Resolve-Path ".\haproxy-schema").Path
.\haproxy-schema\scripts\test-all.ps1
```
