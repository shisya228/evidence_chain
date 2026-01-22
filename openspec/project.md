# Project Context

## Purpose
`evidence_chain` is a Python 3.11 CLI that collects evidence from a directory, generates a manifest/Merkle root/report, and appends each case to a global append-only hash chain for integrity tracking.

## Tech Stack
- Python 3.11 (standard library only)
- CLI entrypoint via `python -m evidence_chain`
- External tools: `openssl` + `curl` for TSA timestamping

## Project Conventions

### Code Style
- Standard-library-only implementation (no third-party deps unless explicitly required).
- Prefer small, pure functions with explicit inputs/outputs.
- Use `sha256:<hex>` prefix for all hash outputs.
- JSON outputs are serialized with sorted keys and stable indentation via `util.atomic_write_json`.

### Architecture Patterns
- CLI orchestration in `evidence_chain/__main__.py`.
- Core scanning + hashing in `evidence_chain/core.py`.
- Append-only chain persistence and verification in `evidence_chain/chain.py`.
- TSA integration isolated in `evidence_chain/tsa.py`.
- Atomic writes for filesystem outputs to avoid partial artifacts.

### Testing Strategy
- Test suite under `tests/` using Python `unittest`.
- Run with `python -m unittest`.
- TSA-related tests skip when `curl`/`openssl` or the TSA endpoint is unavailable.

### Git Workflow
- Use feature branches for changes.
- Commit messages follow conventional style (e.g., `chore:`/`feat:`/`fix:`) and describe intent.

## Domain Context
- Evidence collection is immutable once appended; integrity is enforced by hashing and a chained ledger (`chain.jsonl` + `HEAD.json`).
- Each case captures a manifest, Merkle root, timeline, and report for auditability.
- TSA timestamping is mandatory for collection to establish external time proof.

## Important Constraints
- Append-only chain: never rewrite existing chain entries or case artifacts.
- Avoid filesystem traversal escapes (canonical relative paths only).
- TSA failures must prevent chain append and surface in `run.json`.

## External Dependencies
- TSA endpoint (default `https://freetsa.org/tsr`).
- System `openssl` and `curl` binaries for TSA request/verification.
