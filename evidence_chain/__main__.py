"""Command-line interface for evidence_chain."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List

from . import chain, core, tsa, util


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="evidence_chain")
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect_parser = subparsers.add_parser("collect", help="Collect evidence into a case")
    collect_parser.add_argument("input_dir")
    collect_parser.add_argument("--repo", required=True)
    collect_parser.add_argument("--case-id")
    collect_parser.add_argument("--exclude", action="append", default=[])
    collect_parser.add_argument("--tsa-enabled", choices=["true", "false"], default="true")
    collect_parser.add_argument("--tsa-url", default="https://freetsa.org/")
    collect_parser.add_argument("--timeline-order", choices=["desc", "asc"], default="desc")

    verify_case_parser = subparsers.add_parser("verify-case", help="Verify a collected case")
    verify_case_parser.add_argument("--repo", required=True)
    verify_case_parser.add_argument("--case-id", required=True)
    verify_case_parser.add_argument("--dir")
    verify_case_parser.add_argument("--verify-tsa", choices=["true", "false"], default="true")

    verify_chain_parser = subparsers.add_parser("verify-chain", help="Verify the global chain")
    verify_chain_parser.add_argument("--repo", required=True)

    return parser.parse_args(argv)


def ensure_repo(repo: str) -> None:
    os.makedirs(os.path.join(repo, "cases"), exist_ok=True)
    os.makedirs(os.path.join(repo, "chain"), exist_ok=True)


def collect_command(args: argparse.Namespace) -> int:
    input_dir = os.path.abspath(args.input_dir)
    repo = os.path.abspath(args.repo)
    ensure_repo(repo)
    case_id = args.case_id or f"case-{util.utc_now().replace(':', '').replace('-', '').replace('Z', '')}"
    excludes = core.DEFAULT_EXCLUDES + args.exclude
    started_at = util.utc_now()
    items, stats = core.scan_input(input_dir, excludes)
    manifest_items = core.assign_eids(items)
    leaf_hashes = [item["leaf_hash"] for item in manifest_items]
    manifest_hash_value = core.manifest_hash(leaf_hashes)
    case_root = core.merkle_root(leaf_hashes)

    case_dir = os.path.join(repo, "cases", case_id)
    core.write_case_files(
        case_dir=case_dir,
        case_id=case_id,
        input_dir=input_dir,
        manifest_items=manifest_items,
        manifest_hash_value=manifest_hash_value,
        case_root=case_root,
        timeline_order=args.timeline_order,
        excludes=excludes,
    )

    if args.tsa_enabled != "true":
        print("TSA is required for collection")
        return 1
    tsa_result = {
        "enabled": True,
        "url": args.tsa_url,
        "status": "pending",
        "token_path": None,
        "error": None,
    }
    tsa_dir = os.path.join(case_dir, "tsa")
    response = tsa.request_timestamp(case_root, args.tsa_url, tsa_dir)
    tsa_result["status"] = response["status"]
    tsa_result["token_path"] = response.get("response_path")
    tsa_result["error"] = response.get("error")
    tsa_result["url"] = response.get("url", args.tsa_url)

    run_payload = {
        "started_at_utc": started_at,
        "ended_at_utc": util.utc_now(),
        "stats": {
            "files_hashed": stats.files_hashed,
            "symlinks": stats.symlinks,
            "bytes_read": stats.bytes_read,
            "errors": len(stats.errors),
        },
        "warnings": [],
        "errors": stats.errors,
        "tsa": tsa_result,
    }
    util.atomic_write_json(os.path.join(case_dir, "run.json"), run_payload)
    if tsa_result["status"] != "ok":
        print("TSA request failed; case not appended to chain")
        return 1

    entry = chain.append_entry(repo, case_id, case_root, manifest_hash_value)
    print(json.dumps({"case_id": case_id, "case_root": case_root, "chain_head": entry["entry_hash"]}))
    return 0


def verify_case_command(args: argparse.Namespace) -> int:
    repo = os.path.abspath(args.repo)
    case_id = args.case_id
    case_dir = os.path.join(repo, "cases", case_id)
    manifest_path = os.path.join(case_dir, "manifest.json")
    merkle_path = os.path.join(case_dir, "merkle.json")
    if not os.path.exists(manifest_path):
        print(f"manifest.json not found for case {case_id}")
        return 1
    manifest = core.load_json(manifest_path)
    merkle = core.load_json(merkle_path)
    input_dir = args.dir or manifest.get("input_dir")
    if not input_dir:
        print("Input directory not provided and not stored in manifest")
        return 1
    errors, warnings = core.verify_manifest_items(manifest["items"], input_dir)
    leaf_hashes = core.recompute_leaf_hashes(manifest["items"], input_dir)
    recomputed_root = core.merkle_root(leaf_hashes)
    if recomputed_root != merkle.get("case_root"):
        errors.append("Case root mismatch")

    if args.verify_tsa != "true":
        errors.append("TSA verification is required")
    else:
        tsa_dir = os.path.join(case_dir, "tsa")
        request_path = os.path.join(tsa_dir, "request.tsq")
        response_path = os.path.join(tsa_dir, "response.tsr")
        result = tsa.verify_timestamp(request_path, response_path)
        if result["status"] != "ok":
            errors.append(f"TSA verification failed: {result['error']}")

    if warnings:
        for warning in warnings:
            print(f"WARNING: {warning}")
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("Case verification passed")
    return 0


def verify_chain_command(args: argparse.Namespace) -> int:
    repo = os.path.abspath(args.repo)
    ok, errors = chain.verify_chain(repo)
    if ok:
        print("Chain verification passed")
        return 0
    for error in errors:
        print(f"ERROR: {error}")
    return 1


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.command == "collect":
        return collect_command(args)
    if args.command == "verify-case":
        return verify_case_command(args)
    if args.command == "verify-chain":
        return verify_chain_command(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
