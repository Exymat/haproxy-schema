"""HAPEE release metadata: mapping r1 documentation to OSS LTS base versions."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path

_HAPEE_DOC_BASE = "https://www.haproxy.com/documentation/haproxy-configuration-manual"

# OSS 3.4 is community-only until HAPEE 3.4 ships.
HAPEE_OSS_BASES: tuple[str, ...] = ("2.6", "2.8", "3.0", "3.2")


@dataclass(frozen=True)
class HapeeRelease:
    version: str
    oss_base: str
    doc_slug: str
    source_sha256: str
    # HAPEE "Modules" (module-load / module-path) is not at a fixed chapter:
    # 2.6/2.8 → 3.11, 3.0 → 3.13, 3.2 → 3.5. OSS 3.5 is Peers on older docs.
    extra_global_chapters: tuple[str, ...] = ()

    @property
    def doc_url(self) -> str:
        return f"{_HAPEE_DOC_BASE}/{self.doc_slug}/"


HAPEE_RELEASES: dict[str, HapeeRelease] = {
    "2.6r1": HapeeRelease(
        version="2.6r1",
        oss_base="2.6",
        doc_slug="2-6r1",
        source_sha256="cb74e808a5a96df9d6a2a70809012e13ecc4379a9d74d4c342176ae3307cc144",
        extra_global_chapters=("3.11",),
    ),
    "2.8r1": HapeeRelease(
        version="2.8r1",
        oss_base="2.8",
        doc_slug="2-8r1",
        source_sha256="de93b114564ad7f3f1c1a60557fdd7a1beab76820867184da3f4b2bb2a2948fa",
        extra_global_chapters=("3.11",),
    ),
    "3.0r1": HapeeRelease(
        version="3.0r1",
        oss_base="3.0",
        doc_slug="3-0r1",
        source_sha256="1419cffaf59dc7c8487e3e74d3b75805783c3a688b03c36ae32046a36e86c747",
        extra_global_chapters=("3.13",),
    ),
    "3.2r1": HapeeRelease(
        version="3.2r1",
        oss_base="3.2",
        doc_slug="3-2r1",
        source_sha256="c7c5783c8650e52633a2d48571f8069d55f4b23e34f32d7be8bcba4315543572",
        extra_global_chapters=("3.5",),
    ),
}

HAPEE_RELEASE_BY_OSS_BASE: dict[str, HapeeRelease] = {
    release.oss_base: release for release in HAPEE_RELEASES.values()
}


def hapee_release(version: str) -> HapeeRelease:
    release = HAPEE_RELEASES.get(version)
    if release is None:
        supported = ", ".join(sorted(HAPEE_RELEASES))
        raise ValueError(f"Unsupported HAPEE version {version!r}; supported: {supported}")
    return release


def hapee_release_for_oss_base(oss_base: str) -> HapeeRelease | None:
    return HAPEE_RELEASE_BY_OSS_BASE.get(oss_base)


def hapee_source_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized_hapee_source(html: str) -> str:
    return html.replace("\r\n", "\n").replace("\r", "\n")


def verify_hapee_source_text(html: str, release: HapeeRelease) -> str:
    normalized = normalized_hapee_source(html)
    actual = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    if actual != release.source_sha256:
        raise ValueError(
            f"HAPEE {release.version} source checksum changed: expected "
            f"{release.source_sha256}, got {actual}. Review the upstream manual and "
            "update the pinned checksum deliberately before regenerating artifacts."
        )
    return normalized


def verify_hapee_source(path: Path, release: HapeeRelease) -> None:
    actual = hapee_source_sha256(path)
    if actual != release.source_sha256:
        raise ValueError(
            f"HAPEE {release.version} source checksum changed: expected "
            f"{release.source_sha256}, got {actual}. Review the upstream manual and "
            "update the pinned checksum deliberately before regenerating artifacts."
        )


def default_hapee_html_fixture(version: str) -> Path:
    package_dir = Path(__file__).resolve().parent
    return package_dir / "fixtures" / "hapee" / f"hapee-{version}.html"


def default_oss_configuration_txt(oss_base: str, *, monorepo_root: Path | None = None) -> Path:
    root = monorepo_root or infer_monorepo_root()
    if root is None:
        raise FileNotFoundError(f"Cannot locate haproxy_git for OSS base {oss_base}")
    return root / "haproxy_git" / f"haproxy-{oss_base}" / "doc" / "configuration.txt"


def infer_monorepo_root() -> Path | None:
    for ancestor in Path(__file__).resolve().parents:
        if (ancestor / "haproxy_git").is_dir():
            return ancestor
    return None
