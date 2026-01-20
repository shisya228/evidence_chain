# evidence_chain

`evidence_chain` is a Python 3.11 CLI for collecting evidence from a directory into a case and appending it to a global, append-only hash chain.

## Features

- Scans an input directory without following symlinks.
- Builds a manifest, Merkle root, timeline, report, and run log.
- Appends each case to a global chain (`chain.jsonl` + `HEAD.json`).
- Required TSA timestamping via `openssl` and `curl`.

## Installation

This project uses the standard library only. Install it in a Python 3.11 environment or run it directly with `python -m evidence_chain`.

## Usage

Collect a case:

```bash
python -m evidence_chain collect /path/to/input --repo /path/to/repo
```

Collect with extra excludes:

```bash
python -m evidence_chain collect /path/to/input --repo /path/to/repo \
  --exclude "**/tmp/**" --exclude "**/*.log"
```

Verify a case:

```bash
python -m evidence_chain verify-case --repo /path/to/repo --case-id case-123
```

Verify the global chain:

```bash
python -m evidence_chain verify-chain --repo /path/to/repo
```

## TSA Notes

TSA support is required and uses `openssl` and `curl`. If the URL is the base `https://freetsa.org/`, the tool will automatically target `/tsr`.

```bash
python -m evidence_chain collect /path/to/input --repo /path/to/repo \
  --tsa-enabled true --tsa-url https://freetsa.org/
```

If TSA requests fail, the collect command records the error in `run.json` and exits non-zero.
TSA verification uses the system CA bundle via `openssl ts -verify`.

## Output Layout

Cases are stored under `<repo>/cases/<case_id>/` and include:

- `manifest.json`
- `merkle.json`
- `timeline.md`
- `report.md`
- `run.json`
- `tsa/request.tsq` and `tsa/response.tsr`

The global chain is stored under `<repo>/chain/` in:

- `chain.jsonl`
- `HEAD.json`
