"""Core evidence collection and hashing logic."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Iterable, List, Tuple

from . import util

DEFAULT_EXCLUDES = [
    "**/.git/**",
    "**/node_modules/**",
    "**/__pycache__/**",
    "**/.DS_Store",
    "**/target/**",
    "**/dist/**",
    "**/.venv/**",
]

CHUNK_SIZE = 8 * 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def hash_file(path: str) -> Tuple[str, int]:
    hasher = hashlib.sha256()
    total = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest(), total


def leaf_hash_file(rel_path: str, size: int, mtime_ns: int, digest: str) -> str:
    payload = (
        "leaf-v1\0" + "type=file\0" + f"rel_path={rel_path}\0size={size}\0mtime_ns={mtime_ns}\0digest={digest}\0"
    )
    return sha256_bytes(payload.encode("utf-8"))


def leaf_hash_symlink(rel_path: str, target: str) -> str:
    payload = "leaf-v1\0" + "type=symlink\0" + f"rel_path={rel_path}\0link_target={target}\0"
    return sha256_bytes(payload.encode("utf-8"))


def manifest_hash(leaf_hashes: Iterable[str]) -> str:
    joined = "\n".join(h.split(":", 1)[1] for h in leaf_hashes)
    payload = b"manifest-v1\0" + joined.encode("utf-8")
    return sha256_bytes(payload)


def merkle_root(leaf_hashes: Iterable[str]) -> str:
    leaves = [bytes.fromhex(h.split(":", 1)[1]) for h in leaf_hashes]
    if not leaves:
        return sha256_bytes(b"")
    level = leaves
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        next_level = []
        for idx in range(0, len(level), 2):
            left = level[idx]
            right = level[idx + 1]
            node = hashlib.sha256(b"node-v1\0" + left + right).digest()
            next_level.append(node)
        level = next_level
    return "sha256:" + level[0].hex()


@dataclass
class ScanStats:
    files_hashed: int = 0
    symlinks: int = 0
    bytes_read: int = 0
    errors: List[str] = None

    def __post_init__(self) -> None:
        if self.errors is None:
            self.errors = []


@dataclass
class ScanItem:
    rel_path: str
    item: dict


def is_excluded(rel_path: str, patterns: Iterable[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatch(rel_path, pattern):
            return True
    return False


def scan_input(input_dir: str, excludes: Iterable[str]) -> Tuple[List[ScanItem], ScanStats]:
    items: List[ScanItem] = []
    stats = ScanStats()
    stack = [input_dir]
    patterns = list(excludes)
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    rel_path = util.canonical_relpath(input_dir, entry.path)
                    if not rel_path:
                        continue
                    if is_excluded(rel_path, patterns):
                        if entry.is_dir(follow_symlinks=False):
                            continue
                        continue
                    if entry.is_symlink():
                        try:
                            target = os.readlink(entry.path)
                        except OSError as exc:
                            stats.errors.append(f"Failed to read symlink {rel_path}: {exc}")
                            continue
                        leaf_hash = leaf_hash_symlink(rel_path, target)
                        items.append(
                            ScanItem(
                                rel_path=rel_path,
                                item={
                                    "type": "symlink",
                                    "rel_path": rel_path,
                                    "link_target": target,
                                    "leaf_hash": leaf_hash,
                                    "storage": {"kind": "none"},
                                },
                            )
                        )
                        stats.symlinks += 1
                    elif entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        try:
                            stat = entry.stat(follow_symlinks=False)
                            digest, bytes_read = hash_file(entry.path)
                            leaf_hash = leaf_hash_file(rel_path, stat.st_size, stat.st_mtime_ns, digest)
                            items.append(
                                ScanItem(
                                    rel_path=rel_path,
                                    item={
                                        "type": "file",
                                        "rel_path": rel_path,
                                        "size": stat.st_size,
                                        "mtime_ns": stat.st_mtime_ns,
                                        "mtime_utc": util.utc_from_ns(stat.st_mtime_ns),
                                        "digest": digest,
                                        "leaf_hash": leaf_hash,
                                        "storage": {"kind": "none"},
                                    },
                                )
                            )
                            stats.files_hashed += 1
                            stats.bytes_read += bytes_read
                        except OSError as exc:
                            stats.errors.append(f"Failed to hash file {rel_path}: {exc}")
                    else:
                        continue
        except OSError as exc:
            stats.errors.append(f"Failed to scan {current}: {exc}")
    return items, stats


def assign_eids(items: List[ScanItem]) -> List[dict]:
    sorted_items = sorted(items, key=lambda item: item.rel_path)
    manifest_items: List[dict] = []
    for idx, scan_item in enumerate(sorted_items, start=1):
        eid = f"E{idx:06d}"
        item = dict(scan_item.item)
        item["eid"] = eid
        manifest_items.append(item)
    return manifest_items


def build_timeline(items: List[dict], order: str) -> str:
    file_items = [item for item in items if item["type"] == "file"]
    reverse = order == "desc"
    file_items.sort(key=lambda item: item["mtime_ns"], reverse=reverse)
    lines = []
    for item in file_items:
        digest_prefix = item["digest"].split(":", 1)[1][:12]
        lines.append(f"- {item['mtime_utc']}  {item['eid']}  {item['rel_path']}  {digest_prefix}…")
    return "\n".join(lines) + ("\n" if lines else "")


def build_report(case_id: str, created_at: str, case_root: str, input_dir: str, excludes: Iterable[str]) -> str:
    exclude_list = "\n".join(f"- {pattern}" for pattern in excludes)
    return (
        "# Evidence Report\n\n"
        f"- Case ID: {case_id}\n"
        f"- Created at (UTC): {created_at}\n"
        f"- Case root: {case_root}\n"
        f"- Input directory: {input_dir}\n\n"
        "## Excludes\n"
        f"{exclude_list}\n\n"
        "## Observations\n"
        "facts only; cite [E000001]\n"
    )


def write_case_files(
    case_dir: str,
    case_id: str,
    input_dir: str,
    manifest_items: List[dict],
    manifest_hash_value: str,
    case_root: str,
    timeline_order: str,
    excludes: Iterable[str],
) -> None:
    created_at = util.utc_now()
    manifest_payload = {
        "version": "0.1",
        "case_id": case_id,
        "created_at_utc": created_at,
        "input_dir": input_dir,
        "manifest_hash": manifest_hash_value,
        "items": manifest_items,
    }
    merkle_payload = {
        "version": "0.1",
        "case_id": case_id,
        "alg": "sha256",
        "leaf_hash_scheme": "leaf-v1",
        "node_hash_scheme": "node-v1",
        "leaf_count": len(manifest_items),
        "case_root": case_root,
    }
    timeline = build_timeline(manifest_items, timeline_order)
    report = build_report(case_id, created_at, case_root, input_dir, excludes)

    os.makedirs(case_dir, exist_ok=True)
    util.atomic_write_json(os.path.join(case_dir, "manifest.json"), manifest_payload)
    util.atomic_write_json(os.path.join(case_dir, "merkle.json"), merkle_payload)
    util.atomic_write(os.path.join(case_dir, "timeline.md"), timeline)
    util.atomic_write(os.path.join(case_dir, "report.md"), report)


def verify_manifest_items(items: List[dict], input_dir: str) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    for item in items:
        rel_path = item["rel_path"]
        path = os.path.join(input_dir, rel_path)
        if item["type"] == "file":
            if not os.path.exists(path):
                errors.append(f"Missing file: {rel_path}")
                continue
            if not os.path.isfile(path):
                errors.append(f"Not a file: {rel_path}")
                continue
            digest, _ = hash_file(path)
            if digest != item["digest"]:
                errors.append(f"Digest mismatch: {rel_path}")
        elif item["type"] == "symlink":
            if not os.path.islink(path):
                errors.append(f"Missing symlink: {rel_path}")
                continue
            target = os.readlink(path)
            if target != item["link_target"]:
                errors.append(f"Symlink target mismatch: {rel_path}")
        else:
            warnings.append(f"Unknown item type: {rel_path}")
    return errors, warnings


def recompute_leaf_hashes(items: List[dict], input_dir: str) -> List[str]:
    leaf_hashes: List[str] = []
    for item in items:
        rel_path = item["rel_path"]
        path = os.path.join(input_dir, rel_path)
        if item["type"] == "file" and os.path.isfile(path):
            stat = os.stat(path, follow_symlinks=False)
            digest, _ = hash_file(path)
            leaf_hashes.append(leaf_hash_file(rel_path, stat.st_size, stat.st_mtime_ns, digest))
        elif item["type"] == "symlink" and os.path.islink(path):
            target = os.readlink(path)
            leaf_hashes.append(leaf_hash_symlink(rel_path, target))
        else:
            leaf_hashes.append(item["leaf_hash"])
    return leaf_hashes


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)
