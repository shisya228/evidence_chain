"""Utility helpers for evidence_chain."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utc_from_ns(ns: int) -> str:
    return datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def canonical_relpath(base_dir: str, path: str) -> str:
    rel_path = os.path.relpath(path, base_dir)
    rel_path = rel_path.replace(os.sep, "/")
    if rel_path == ".":
        return ""
    if rel_path.startswith("../") or rel_path == ".." or "/../" in rel_path:
        raise ValueError(f"Unsafe rel_path computed: {rel_path}")
    if rel_path.startswith("./"):
        rel_path = rel_path[2:]
    return rel_path


def atomic_write(path: str, data: str) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=directory) as handle:
        handle.write(data)
        temp_path = handle.name
    os.replace(temp_path, path)


def atomic_write_json(path: str, payload: Any, indent: int = 2) -> None:
    data = json.dumps(payload, sort_keys=True, indent=indent) + "\n"
    atomic_write(path, data)
