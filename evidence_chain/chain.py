"""Append-only chain management."""

from __future__ import annotations

import json
import os
from typing import List, Tuple

import fcntl
import hashlib

from . import util

ZERO_HASH = "sha256:" + "0" * 64


def entry_hash(seq: int, time_utc: str, case_id: str, case_root: str, manifest_hash: str, prev: str) -> str:
    payload = (
        "entry-v1\0"
        + f"seq={seq}\0time_utc={time_utc}\0case_id={case_id}\0case_root={case_root}\0"
        + f"manifest_hash={manifest_hash}\0prev={prev}\0"
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _read_last_entry(chain_path: str) -> Tuple[int, str]:
    if not os.path.exists(chain_path):
        return 0, ZERO_HASH
    with open(chain_path, "r", encoding="utf-8") as handle:
        lines = [line.strip() for line in handle if line.strip()]
    if not lines:
        return 0, ZERO_HASH
    last = json.loads(lines[-1])
    return int(last["seq"]), last["entry_hash"]


def append_entry(repo: str, case_id: str, case_root: str, manifest_hash: str, time_utc: str | None = None) -> dict:
    chain_dir = os.path.join(repo, "chain")
    os.makedirs(chain_dir, exist_ok=True)
    lock_path = os.path.join(chain_dir, ".lock")
    chain_path = os.path.join(chain_dir, "chain.jsonl")
    head_path = os.path.join(chain_dir, "HEAD.json")
    time_utc = time_utc or util.utc_now()
    with open(lock_path, "a+") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        seq, prev = _read_last_entry(chain_path)
        seq += 1
        entry = {
            "v": 1,
            "seq": seq,
            "time_utc": time_utc,
            "case_id": case_id,
            "case_root": case_root,
            "manifest_hash": manifest_hash,
            "prev": prev,
        }
        entry["entry_hash"] = entry_hash(
            entry["seq"],
            entry["time_utc"],
            entry["case_id"],
            entry["case_root"],
            entry["manifest_hash"],
            entry["prev"],
        )
        with open(chain_path, "a", encoding="utf-8") as chain_file:
            chain_file.write(json.dumps(entry, sort_keys=True) + "\n")
        head_payload = {"v": 1, "head": entry["entry_hash"], "seq": seq, "updated_at_utc": util.utc_now()}
        util.atomic_write_json(head_path, head_payload)
        fcntl.flock(lock_file, fcntl.LOCK_UN)
    return entry


def verify_chain(repo: str) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    chain_path = os.path.join(repo, "chain", "chain.jsonl")
    head_path = os.path.join(repo, "chain", "HEAD.json")
    prev = ZERO_HASH
    last_entry = None
    if not os.path.exists(chain_path):
        errors.append("chain.jsonl missing")
        return False, errors
    with open(chain_path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            entry = json.loads(line)
            expected_hash = entry_hash(
                entry["seq"],
                entry["time_utc"],
                entry["case_id"],
                entry["case_root"],
                entry["manifest_hash"],
                entry["prev"],
            )
            if entry["entry_hash"] != expected_hash:
                errors.append(f"Entry hash mismatch at line {line_number}")
            if entry["prev"] != prev:
                errors.append(f"Prev hash mismatch at line {line_number}")
            if last_entry and entry["seq"] != last_entry["seq"] + 1:
                errors.append(f"Sequence mismatch at line {line_number}")
            prev = entry["entry_hash"]
            last_entry = entry
    if last_entry and os.path.exists(head_path):
        with open(head_path, "r", encoding="utf-8") as handle:
            head = json.load(handle)
        if head.get("head") != last_entry["entry_hash"]:
            errors.append("HEAD.json does not match last entry")
        if head.get("seq") != last_entry["seq"]:
            errors.append("HEAD.json seq does not match last entry")
    if errors:
        return False, errors
    return True, []
