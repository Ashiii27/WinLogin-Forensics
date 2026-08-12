"""
WinLogin Forensics - Report Integrity
=====================================================
Chain-of-custody logging, SHA-256 hashing, digital signing, and optional
RFC 3161 trusted timestamping for generated forensic reports.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


TOOL_NAME = "WinLogin Forensics"
TOOL_VERSION = "0.1.0"
DEFAULT_TSA_URL = "https://freetsa.org/tsr"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def compute_sha256(data: Union[str, bytes]) -> str:
    """Compute SHA-256 hex digest of string or bytes content."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hash_file(file_path: Union[str, Path]) -> str:
    """Compute SHA-256 hash of a file on disk."""
    path = Path(file_path)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class ChainOfCustody:
    """
    Records forensic chain-of-custody metadata for an analysis run.
    Written on every report generation: tool version, operator, parameters,
    source files, and output files.
    """

    def __init__(
        self,
        operator: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ):
        self.started_at = utc_now_iso()
        self.operator = operator or getpass.getuser()
        self.hostname = socket.gethostname()
        self.platform = platform.platform()
        self.tool_name = TOOL_NAME
        self.tool_version = TOOL_VERSION
        self.parameters = parameters or {}
        self.source_files: List[Dict[str, str]] = []
        self.output_files: List[Dict[str, str]] = []
        self.completed_at: Optional[str] = None

    def add_source_file(self, path: Union[str, Path], file_hash: Optional[str] = None) -> None:
        p = Path(path)
        entry = {
            "path": str(p.resolve()) if p.exists() else str(p),
            "filename": p.name,
            "sha256": file_hash or (hash_file(p) if p.is_file() else ""),
            "size_bytes": str(p.stat().st_size) if p.is_file() else "0",
        }
        self.source_files.append(entry)

    def add_output_file(self, path: Union[str, Path], file_hash: Optional[str] = None) -> None:
        p = Path(path)
        entry = {
            "path": str(p.resolve()) if p.exists() else str(p),
            "filename": p.name,
            "sha256": file_hash or (hash_file(p) if p.is_file() else ""),
        }
        self.output_files.append(entry)

    def finalize(self) -> Dict[str, Any]:
        self.completed_at = utc_now_iso()
        return self.to_dict()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "operator": self.operator,
            "hostname": self.hostname,
            "platform": self.platform,
            "parameters": self.parameters,
            "source_files": self.source_files,
            "output_files": self.output_files,
        }

    def save(self, output_path: Union[str, Path]) -> Path:
        """Persist chain-of-custody record as JSON."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        record = self.finalize()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, default=str)
        self.add_output_file(path, compute_sha256(json.dumps(record, default=str)))
        return path


class ReportIntegrity:
    """
    Handles report content hashing, optional RSA signing, and RFC 3161 timestamping.
    """

    def __init__(
        self,
        sign: bool = False,
        timestamp: bool = False,
        tsa_url: str = DEFAULT_TSA_URL,
        private_key_path: Optional[Union[str, Path]] = None,
    ):
        self.sign = sign
        self.timestamp = timestamp
        self.tsa_url = tsa_url
        self.private_key_path = Path(private_key_path) if private_key_path else None
        self.content_hash: Optional[str] = None
        self.signature: Optional[str] = None
        self.timestamp_token: Optional[str] = None
        self.timestamp_error: Optional[str] = None

    def hash_content(self, content: Union[str, bytes]) -> str:
        self.content_hash = compute_sha256(content)
        return self.content_hash

    def sign_hash(self, content_hash: Optional[str] = None) -> Optional[str]:
        """Sign the report SHA-256 hash with RSA-PSS. Returns base64 signature."""
        if not self.sign:
            return None
        if not CRYPTO_AVAILABLE:
            raise RuntimeError(
                "cryptography library required for report signing. "
                "Install with: pip install cryptography"
            )

        digest_hex = content_hash or self.content_hash
        if not digest_hex:
            raise ValueError("No content hash available to sign.")

        private_key = self._load_or_generate_key()
        digest_bytes = bytes.fromhex(digest_hex)
        signature_bytes = private_key.sign(
            digest_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(hashes.SHA256()),
        )
        self.signature = base64.b64encode(signature_bytes).decode("ascii")
        return self.signature

    def request_timestamp(self, content_hash: Optional[str] = None) -> Optional[str]:
        """
        Submit report hash to a trusted timestamp authority (RFC 3161).
        Uses FreeTSA by default; requires network access.
        """
        if not self.timestamp:
            return None
        if not REQUESTS_AVAILABLE:
            self.timestamp_error = "requests library not installed"
            return None

        digest = content_hash or self.content_hash
        if not digest:
            raise ValueError("No content hash available for timestamping.")

        try:
            response = requests.post(
                self.tsa_url,
                data=bytes.fromhex(digest),
                headers={"Content-Type": "application/timestamp-query"},
                timeout=30,
            )
            response.raise_for_status()
            self.timestamp_token = base64.b64encode(response.content).decode("ascii")
            return self.timestamp_token
        except Exception as exc:
            self.timestamp_error = str(exc)
            return None

    def process(self, content: Union[str, bytes]) -> Dict[str, Any]:
        """
        Full integrity pipeline: hash -> optional sign -> optional timestamp.
        Returns integrity block dict for embedding in reports.
        """
        content_hash = self.hash_content(content)
        signature = self.sign_hash(content_hash) if self.sign else None
        ts_token = self.request_timestamp(content_hash) if self.timestamp else None

        return {
            "sha256": content_hash,
            "signed": self.sign and signature is not None,
            "signature": signature,
            "timestamped": self.timestamp and ts_token is not None,
            "timestamp_token": ts_token,
            "timestamp_error": self.timestamp_error,
            "tsa_url": self.tsa_url if self.timestamp else None,
            "generated_at": utc_now_iso(),
        }

    def _load_or_generate_key(self):
        if self.private_key_path and self.private_key_path.is_file():
            pem = self.private_key_path.read_bytes()
            return serialization.load_pem_private_key(pem, password=None, backend=default_backend())

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        if self.private_key_path:
            self.private_key_path.parent.mkdir(parents=True, exist_ok=True)
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            self.private_key_path.write_bytes(pem)
            try:
                os.chmod(self.private_key_path, 0o600)
            except OSError:
                pass
        return key
