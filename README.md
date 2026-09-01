# haproxy-schema

[![License](https://img.shields.io/github/license/Exymat/haproxy-schema)](LICENSE)

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
| `haproxy-X.Y.tmLanguage.json` | Fully generated TextMate grammar for syntax highlighting |
| `coverage-X.Y.json` | Doc vs dkall gap report (keywords missing from either side) |

**2.6** and **2.8** use the legacy `configuration.txt` layout: rule actions are listed inline under each proxy keyword in §4.2 rather than in the separate §4.3/§4.4 reference used from 3.0 onward. The parser detects this automatically (`doc_layout.py`, `legacy_action_parser.py`).

## Repository layout

```
haproxy-schema/
  .github/workflows/     # GitHub Actions (build + test per HAProxy release)
  .python-version        # pinned Python for uv and CI (3.13)
  uv.lock                # locked dev dependencies (pytest, pytest-cov)
  haproxy_schema/        # importable package (CLI: uv run haproxy-schema)
    dkall-2.6.txt        # checked-in -dKall dumps
    dkall-2.8.txt
    dkall-3.0.txt
    dkall-3.2.txt
    dkall-3.4.txt
    coverage-2.6.json    # doc vs dkall gap reports (written by build)
    coverage-2.8.json
    coverage-3.0.json
    coverage-3.2.json
    coverage-3.4.json
    doc-parse-audit-*.json       # checked-in doc-parse audit snapshots
    schema-fidelity-audit-*.json # checked-in schema-fidelity audit snapshots
    tests/
      _paths.py          # SUPPORTED_VERSIONS and monorepo path helpers
  scripts/               # dkall generation, optional binary install, test runner
```

Dependencies and the virtual environment are managed with [uv](https://docs.astral.sh/uv/). Install uv, then from the repository root:

```bash
cd haproxy-schema
uv sync --locked --dev
uv run haproxy-schema build --help
uv run pytest
```

On Windows (PowerShell):

```powershell
cd haproxy-schema
uv sync --locked --dev
uv run haproxy-schema build --help
uv run pytest
```

`uv run pytest` writes a terminal summary plus HTML (`htmlcov/index.html`) and XML (`coverage.xml`) reports. Current coverage is about **98%**; thresholds are not enforced in CI yet.

## Testing

The suite has **389 tests** covering parsing, schema merge, grammar emission, CLI commands, and audit snapshots. Many integration tests are parametrized over all five supported releases (`2.6`, `2.8`, `3.0`, `3.2`, `3.4`); the canonical version list lives in `haproxy_schema/tests/_paths.py` as `SUPPORTED_VERSIONS`.

`haproxy_schema/tests/test_per_version.py` runs end-to-end checks for every release: doc parsing, layout detection, schema merge, language data, coverage reports, schema invariants, audit artifacts, and JSON round-trip.

Full runs expect a **monorepo-style sibling layout** under the same parent directory:

| Path | Purpose |
| ---- | ------- |
| `../haproxy_git/haproxy-<version>/` | upstream `configuration.txt` per release |
| `../haproxy-vscode/schemas/haproxy-<version>.schema.json` | built schema artifacts consumed by grammar and validator tests |

Tests skip gracefully when a source tree or schema file is missing. To run everything locally, clone [haproxy-vscode](https://github.com/Exymat/haproxy-vscode) and the HAProxy version repos as siblings (see below), build schemas, then run `uv run pytest`.

From a parent directory that contains both repos, `scripts/test-all.ps1` runs pytest with coverage and, when **haproxy-vscode** is present, grammar checks plus the extension's npm test suite.

## Continuous integration

GitHub Actions workflow [`.github/workflows/test.yml`](.github/workflows/test.yml) runs on every push and pull request (markdown changes are ignored):

| Job | What it does |
| --- | ------------ |
| **Build** (matrix: 2.6, 2.8, 3.0, 3.2, 3.4) | Clones upstream HAProxy source, builds schema/language/grammar artifacts, runs `check-grammar` |
| **Tests** | Clones all five HAProxy trees, builds schemas, runs the full pytest suite with coverage |

CI uses [actions/setup-python](https://github.com/actions/setup-python) with `.python-version`, [astral-sh/setup-uv](https://github.com/astral-sh/setup-uv) (uv **0.11.19**, locked sync, cache enabled), and uploads `coverage.xml` to Codecov. Upstream HAProxy sources are fetched from `git.haproxy.org` at job time; no sibling checkout is required on the runner beyond what the workflow creates under `../haproxy_git/`, `../haproxy-vscode/schemas/`, and `../haproxy-vscode/syntaxes/`.

## CLI

| Command | Description |
| ------- | ----------- |
| `build` | Merge `configuration.txt` + dkall dump into schema JSON; optionally emit language data, grammar, and coverage report |
| `build-hapee` | Parse official HAPEE HTML docs and write full schema/language artifacts (`haproxy-X.Yr1.schema.json`) for LTS 2.6r1–3.2r1 |
| `emit-grammar` | Regenerate a fully generated TextMate grammar from an existing schema JSON |
| `check-grammar` | Verify an emitted grammar covers all schema directives (prefix conflicts, missing cache keywords, stale hyphen forms) |
| `audit-docs` | Report bind/server/proxy options missing hover documentation |
| `doc-parse-audit` | Audit `configuration.txt` extraction quality for docs, signatures, hover payloads, and action references |
| `schema-fidelity-audit` | Audit how completely keyword arguments, nested options, sample functions, and value-taking options are modeled in schema JSON |

The grammar generator is self-contained: it does not fetch or patch any upstream tmLanguage template at build time. Generated grammars point `$schema` to a local sidecar file, `./tmlanguage.schema.json`, which is emitted beside each `haproxy-X.Y.tmLanguage.json`.

Example — build schema for 3.2 (paths assume sibling `haproxy_git/` trees):

```bash
uv run haproxy-schema build \
  --doc ../haproxy_git/haproxy-3.2/doc/configuration.txt \
  --dkall haproxy_schema/dkall-3.2.txt \
  --out /tmp/haproxy-3.2.schema.json \
  --language-data-out /tmp/haproxy-3.2.language.json \
  --grammar-out /tmp/haproxy-3.2.tmLanguage.json \
  --coverage-out haproxy_schema/coverage-3.2.json \
  --version 3.2
```

HAPEE LTS **2.6r1–3.2r1** is built as a complete OSS-base overlay: community keywords/actions/sample functions are preserved, the Enterprise manual overrides or extends them, and optional-module syntax that cannot appear in the OSS `-dkall` dump is applied from a versioned overlay. That overlay covers WAF and response-body injection in every supported release, UDP from 2.8r1, SAML/Captcha/Bot Management from 3.0r1, and OIDC/RHI from 3.2r1. The VS Code extension loads `haproxy-X.Yr1` schema, language, and grammar files when `haproxy.edition` is `hapee`. `--grammar-out` should target `haproxy-X.Yr1.tmLanguage.json`, never the community `haproxy-X.Y.tmLanguage.json` files.

| HAPEE | OSS base | Schema / language / grammar files | Docs |
| ----- | -------- | -------------------------------- | ---- |
| 2.6r1 | 2.6 | `haproxy-2.6r1.schema.json`, `haproxy-2.6r1.language.json`, `haproxy-2.6r1.tmLanguage.json` | `https://www.haproxy.com/documentation/haproxy-configuration-manual/2-6r1/` |
| 2.8r1 | 2.8 | `haproxy-2.8r1.schema.json`, `haproxy-2.8r1.language.json`, `haproxy-2.8r1.tmLanguage.json` | `https://www.haproxy.com/documentation/haproxy-configuration-manual/2-8r1/` |
| 3.0r1 | 3.0 | `haproxy-3.0r1.schema.json`, `haproxy-3.0r1.language.json`, `haproxy-3.0r1.tmLanguage.json` | `https://www.haproxy.com/documentation/haproxy-configuration-manual/3-0r1/` |
| 3.2r1 | 3.2 | `haproxy-3.2r1.schema.json`, `haproxy-3.2r1.language.json`, `haproxy-3.2r1.tmLanguage.json` | `https://www.haproxy.com/documentation/haproxy-configuration-manual/3-2r1/` |

Community OSS **3.4** has no HAPEE artifacts (HAPEE 3.4 is not released).

```bash
uv run haproxy-schema build-hapee \
  --hapee-version 3.2r1 \
  --fetch \
  --dkall haproxy_schema/dkall-3.2.txt \
  --out ../haproxy-vscode/schemas/haproxy-3.2r1.schema.json \
  --language-data-out ../haproxy-vscode/schemas/haproxy-3.2r1.language.json \
  --grammar-out ../haproxy-vscode/syntaxes/haproxy-3.2r1.tmLanguage.json
```

`--fetch` downloads the HAPEE configuration manual HTML (old dconv renderer, not `/new/`). Its SHA-256 is pinned per release, so an upstream edit fails the build until reviewed; `--allow-unpinned-html` exists only for custom fixtures and parser development. Full HTML is cached locally and not committed. From **haproxy-vscode**, `npm run generate:schema:hapee` rebuilds all four HAPEE schema, language, and grammar files through the locked `uv` environment.

```bash
uv run haproxy-schema doc-parse-audit \
  --doc ../haproxy_git/haproxy-3.2/doc/configuration.txt \
  --dkall haproxy_schema/dkall-3.2.txt \
  --version 3.2 \
  --out haproxy_schema/doc-parse-audit-3.2.json

uv run haproxy-schema schema-fidelity-audit \
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
  haproxy_git/             # haproxy-2.6/, haproxy-2.8/, haproxy-3.0/, … for doc sources and integration tests
```

Schema build and full test instructions live in [haproxy-vscode/README.md](../haproxy-vscode/README.md). From the parent directory:

```powershell
.\haproxy-schema\scripts\test-all.ps1
```

This runs `uv run pytest` (with coverage), then `check-grammar` for each built schema, then `npm test` in **haproxy-vscode** when that sibling repo is present.

---

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for third-party attributions.

## Data sources

Build outputs combine factual keyword inventories and documentation excerpts from upstream HAProxy releases:

| Source | Origin | Upstream license |
| ------ | ------ | ---------------- |
| `configuration.txt` | Official HAProxy configuration reference per release | GPL-2.0-or-later |
| `haproxy -dKall` | Keyword dump from a DEBUG-enabled HAProxy binary | GPL-2.0-or-later |
| Keyword-line parsing | Adapted from [haproxy-dconv](https://github.com/cbonte/haproxy-dconv) (`dconv_bridge.py`) | Apache-2.0 |

This tooling is independent of the HAProxy program itself; it does not link to or embed HAProxy binaries in its source tree.
