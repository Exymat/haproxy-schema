"""Resolve repo roots for tests (standalone haproxy-schema or monorepo layout)."""

from __future__ import annotations

from pathlib import Path

_SCHEMA_REPO = Path(__file__).resolve().parents[2]

# HAProxy releases this package builds schemas for (see README).
SUPPORTED_VERSIONS: tuple[str, ...] = ("2.6", "2.8", "3.0", "3.2", "3.4")

# HAPEE LTS releases (OSS 3.4 has no HAPEE release yet).
HAPEE_VERSIONS: tuple[str, ...] = ("2.6r1", "2.8r1", "3.0r1", "3.2r1")

# Legacy docs (2.6/2.8) vs modern §4.3/§4.4 reference (3.0+).
LEGACY_DOC_VERSIONS: frozenset[str] = frozenset({"2.6", "2.8"})
MODERN_DOC_VERSIONS: frozenset[str] = frozenset({"3.0", "3.2", "3.4"})


def schema_repo_root() -> Path:
    return _SCHEMA_REPO


def monorepo_root() -> Path | None:
    parent = _SCHEMA_REPO.parent
    return parent if (parent / "haproxy_git").is_dir() else None


def haproxy_vscode_root() -> Path:
    mono = monorepo_root()
    if mono is not None:
        return mono / "haproxy-vscode"
    sibling = _SCHEMA_REPO.parent / "haproxy-vscode"
    return sibling


def hapee_root() -> Path | None:
    path = _SCHEMA_REPO.parent / "HAPEE"
    return path if path.is_dir() else None


def hapee_schema(version: str) -> Path:
    release = version if version.endswith("r1") else f"{version}r1"
    return haproxy_vscode_root() / "schemas" / f"haproxy-{release}.schema.json"


def hapee_language(version: str) -> Path:
    release = version if version.endswith("r1") else f"{version}r1"
    return haproxy_vscode_root() / "schemas" / f"haproxy-{release}.language.json"


def dkall_dump(version: str) -> Path:
    return _SCHEMA_REPO / "haproxy_schema" / f"dkall-{version}.txt"


def haproxy_configuration_txt(version: str) -> Path:
    root = monorepo_root() or _SCHEMA_REPO.parent
    return root / "haproxy_git" / f"haproxy-{version}" / "doc" / "configuration.txt"
