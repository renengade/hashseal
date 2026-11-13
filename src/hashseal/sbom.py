"""Minimal CycloneDX SBOM generation from a signed manifest."""

from __future__ import annotations

from pathlib import Path

from . import __version__
from .core import MANIFEST_NAME, now_iso
from .manifest import parse_manifest


def build_sbom(root: Path) -> dict:
    manifest = root / MANIFEST_NAME
    entries = parse_manifest(manifest)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": now_iso(),
            "tools": [{"vendor": "hashseal", "name": "hashseal", "version": __version__}],
            "component": {"type": "application", "name": root.name},
        },
        "components": [
            {
                "type": "file",
                "name": rel,
                "hashes": [{"alg": "SHA-256", "content": digest}],
            }
            for digest, rel in entries
        ],
    }
