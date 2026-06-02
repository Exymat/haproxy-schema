# haproxy-schema

Python package that builds HAProxy **3.0** / **3.2** schemas, language data, and TextMate grammars from `configuration.txt` and `haproxy -dKall` keyword dumps.

## Repository layout

```
haproxy-schema/
  haproxy_schema/          # importable package (CLI: python -m haproxy_schema)
    dkall-3.0.txt          # checked-in -dKall dumps
    dkall-3.2.txt
    coverage-3.0.json      # doc vs dkall gap reports (written by build)
    coverage-3.2.json
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

## Regenerate dkall dumps

Requires a DEBUG-enabled `haproxy` binary (Debian/Ubuntu packages usually work, or `scripts/install-haproxy-binary.sh`).

```bash
./scripts/generate-dkall.sh 3.2
./scripts/generate-dkall.sh 3.0
```

On Windows, the same script runs inside WSL via `scripts/generate-dkall.ps1` (used by `npm run generate:dkall:*` in **haproxy-vscode**).

If a parent directory also contains `haproxy_git/haproxy-<version>/`, the script uses that tree’s `tests/conf/basic-check.cfg`; otherwise it uses `/dev/null` (non-zero exit is normal). If `-dKall` prints only usage text, the binary lacks DEBUG.

## VS Code extension

The **haproxy-vscode** extension consumes generated `schema.json`, `language.json`, and grammar files. Clone both repositories as siblings under the same parent directory:

```
parent/
  haproxy-schema/
  haproxy-vscode/
  haproxy_git/             # optional: haproxy-3.0/, haproxy-3.2/ for doc + integration tests
```

Schema build and full test instructions live in [haproxy-vscode/README.md](../haproxy-vscode/README.md). From the parent directory:

```powershell
$env:PYTHONPATH = (Resolve-Path ".\haproxy-schema").Path
.\haproxy-schema\scripts\test-all.ps1
```
