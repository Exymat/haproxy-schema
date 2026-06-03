"""Resolve repo roots for tests (standalone haproxy-schema or monorepo layout)."""

from __future__ import annotations

from pathlib import Path

_SCHEMA_REPO = Path(__file__).resolve().parents[2]


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


def dkall_dump(version: str) -> Path:
    return _SCHEMA_REPO / "haproxy_schema" / f"dkall-{version}.txt"


def haproxy_configuration_txt(version: str) -> Path:
    root = monorepo_root() or _SCHEMA_REPO.parent
    return root / "haproxy_git" / f"haproxy-{version}" / "doc" / "configuration.txt"
