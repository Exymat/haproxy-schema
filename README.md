# haproxy-schema

Python package that builds HAProxy **3.0** / **3.2** schemas, language data, and TextMate grammars from `configuration.txt` and `haproxy -dKall` keyword dumps.

## Layout

- `haproxy_schema/` — parsers, merge logic, CLI (`python -m haproxy_schema`)
- `haproxy_schema/dkall-3.0.txt`, `dkall-3.2.txt` — checked-in `-dKall` dumps (regenerate with `scripts/generate-dkall.sh`)
- `scripts/` — dkall generation, optional binary install, test runner

## Quick start

```bash
export PYTHONPATH="$(pwd)"
python -m haproxy_schema build --help
python -m pytest haproxy_schema/tests -q
```

Regenerate a dkall dump (requires DEBUG-enabled `haproxy`, usually from Debian/Ubuntu packages or `scripts/install-haproxy-binary.sh`):

```bash
./scripts/generate-dkall.sh 3.2
```

If a monorepo checkout includes `haproxy_git/haproxy-<version>/`, the script uses that tree’s `tests/conf/basic-check.cfg`; otherwise it uses `/dev/null`.

## VS Code extension

The **haproxy-vscode** extension consumes generated `schema.json` and `language.json` files. Clone both repositories side by side for end-to-end development.
