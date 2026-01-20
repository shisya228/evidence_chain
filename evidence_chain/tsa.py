"""TSA integration via openssl and curl."""

from __future__ import annotations

import os
import ssl
from urllib.parse import urlparse, urlunparse
import subprocess
from typing import Dict, Optional


def request_timestamp(case_root: str, tsa_url: str, tsa_dir: str) -> Dict[str, Optional[str]]:
    os.makedirs(tsa_dir, exist_ok=True)
    request_path = os.path.join(tsa_dir, "request.tsq")
    response_path = os.path.join(tsa_dir, "response.tsr")
    case_root_hex = case_root.split(":", 1)[1]
    parsed = urlparse(tsa_url)
    if parsed.path in ("", "/"):
        parsed = parsed._replace(path="/tsr")
    tsa_url = urlunparse(parsed)
    try:
        subprocess.run(
            [
                "openssl",
                "ts",
                "-query",
                "-digest",
                case_root_hex,
                "-sha256",
                "-cert",
                "-no_nonce",
                "-out",
                request_path,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        return {
            "status": "failed",
            "error": f"openssl failed: {exc.stderr.strip() or exc}",
            "request_path": None,
            "response_path": None,
            "url": tsa_url,
        }
    try:
        subprocess.run(
            [
                "curl",
                "-sS",
                "--fail",
                "--data-binary",
                f"@{request_path}",
                "-H",
                "Content-Type: application/timestamp-query",
                tsa_url,
                "-o",
                response_path,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        return {
            "status": "failed",
            "error": f"curl failed: {exc.stderr.strip() or exc}",
            "request_path": request_path,
            "response_path": None,
            "url": tsa_url,
        }

    return {
        "status": "ok",
        "error": None,
        "request_path": request_path,
        "response_path": response_path,
        "url": tsa_url,
    }


def verify_timestamp(
    request_path: str, response_path: str, ca_file: Optional[str] = None, ca_path: Optional[str] = None
) -> Dict[str, Optional[str]]:
    if not os.path.exists(request_path):
        return {"status": "failed", "error": "request.tsq missing"}
    if not os.path.exists(response_path):
        return {"status": "failed", "error": "response.tsr missing"}
    if ca_file is None and ca_path is None:
        verify_paths = ssl.get_default_verify_paths()
        ca_file = verify_paths.cafile if verify_paths.cafile and os.path.exists(verify_paths.cafile) else None
        ca_path = verify_paths.capath if verify_paths.capath and os.path.exists(verify_paths.capath) else None
    cmd = [
        "openssl",
        "ts",
        "-verify",
        "-in",
        response_path,
        "-queryfile",
        request_path,
    ]
    if ca_file:
        cmd.extend(["-CAfile", ca_file])
    elif ca_path:
        cmd.extend(["-CApath", ca_path])
    else:
        return {"status": "failed", "error": "No CA bundle available for TSA verification"}
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        return {"status": "failed", "error": f"openssl verify failed: {exc.stderr.strip() or exc}"}
    return {"status": "ok", "error": None}
