"""
WinLogin Forensics - Report integrity & chain of custody
========================================================
Records operator / host / command line / SHA-256 of every input, appends a
signed entry for each analysis action, optionally signs the final report
with RSA-PSS, and can submit the hash to an RFC 3161 TSA.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import json
import os
import platform
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

    CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    CRYPTO_AVAILABLE = False

try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:  # pragma: no cover
    REQUESTS_AVAILABLE = False


TOOL_NAME = "WinLogin Forensics"
TOOL_VERSION = "1.0.0"
DEFAULT_TSA_URL = "https://freetsa.org/tsr"


def utc_now_iso() -> str:
    """Return the current UTC time as ``YYYY-MM-DD HH:MM:SS UTC``."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def compute_sha256(data: Union[str, bytes]) -> str:
    """
    SHA-256 hex digest of in-memory content.

    Parameters
    ----------
    data : str | bytes
        Content to hash.

    Returns
    -------
    str
        Hex digest.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def hash_file(file_path: Union[str, Path]) -> str:
    """
    SHA-256 hex digest of a file on disk.

    Parameters
    ----------
    file_path : str | Path
        File to hash.

    Returns
    -------
    str
        Hex digest.
    """
    path = Path(file_path)
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate_rsa_key(path: Optional[Union[str, Path]] = None):
    """
    Generate (or load) a 2048-bit RSA key for PSS report signing.

    Parameters
    ----------
    path : str | Path, optional
        PEM destination / source.

    Returns
    -------
    RSA private key
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography is required for report signing")
    if path:
        p = Path(path)
        if p.is_file():
            return serialization.load_pem_private_key(p.read_bytes(), password=None, backend=default_backend())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    if path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        p.write_bytes(pem)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    return key


def sign_bytes_pss(data: bytes, private_key) -> str:
    """
    Sign ``data`` with RSA-PSS / SHA-256.

    Parameters
    ----------
    data : bytes
        Raw report bytes (or a SHA-256 digest — see ``prehashed``).
    private_key
        RSA private key.

    Returns
    -------
    str
        Base64-encoded signature.
    """
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


class ChainOfCustody:
    """
    Forensic chain-of-custody log.

    The log is the first thing initialised on startup and the last thing
    written before exit. Every analysis action (parse, correlate, detect,
    report) appends a signed entry.
    """

    def __init__(
        self,
        operator: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        output_path: Optional[Union[str, Path]] = None,
        private_key=None,
    ):
        self.started_at = utc_now_iso()
        self.operator = operator or getpass.getuser()
        self.hostname = socket.gethostname()
        self.platform = platform.platform()
        self.command_line = " ".join(sys.argv)
        self.tool_name = TOOL_NAME
        self.tool_version = TOOL_VERSION
        self.parameters = parameters or {}
        self.source_files: List[Dict[str, str]] = []
        self.output_files: List[Dict[str, str]] = []
        self.actions: List[Dict[str, Any]] = []
        self.completed_at: Optional[str] = None
        self.output_path = Path(output_path) if output_path else None
        self.private_key = private_key
        self.log_action("startup", "Chain of custody initialised")

    def add_source_file(self, path: Union[str, Path], file_hash: Optional[str] = None) -> None:
        """Record an input evidence file and its SHA-256."""
        p = Path(path)
        entry = {
            "path": str(p.resolve()) if p.exists() else str(p),
            "filename": p.name,
            "sha256": file_hash or (hash_file(p) if p.is_file() else ""),
            "size_bytes": str(p.stat().st_size) if p.is_file() else "0",
        }
        self.source_files.append(entry)
        self.log_action("ingest", f"{p.name} sha256={entry['sha256']}")

    def add_output_file(self, path: Union[str, Path], file_hash: Optional[str] = None) -> None:
        """Record a generated artefact and its SHA-256."""
        p = Path(path)
        entry = {
            "path": str(p.resolve()) if p.exists() else str(p),
            "filename": p.name,
            "sha256": file_hash or (hash_file(p) if p.is_file() else ""),
        }
        self.output_files.append(entry)
        self.log_action("output", f"{p.name} sha256={entry['sha256']}")

    def log_action(self, action: str, detail: str = "") -> Dict[str, Any]:
        """
        Append a (optionally signed) analysis-action entry.

        Parameters
        ----------
        action : str
            One of ``startup``, ``parse``, ``correlate``, ``detect``,
            ``report``, ``ingest``, ``output``, ``shutdown``.
        detail : str
            Free-text detail.

        Returns
        -------
        dict
            The entry that was appended.
        """
        entry: Dict[str, Any] = {
            "action": action,
            "detail": detail,
            "timestamp": utc_now_iso(),
            "operator": self.operator,
        }
        payload = json.dumps(entry, sort_keys=True).encode("utf-8")
        if self.private_key is not None and CRYPTO_AVAILABLE:
            try:
                entry["signature"] = sign_bytes_pss(payload, self.private_key)
            except Exception as exc:
                entry["signature_error"] = str(exc)
        else:
            entry["integrity_hash"] = compute_sha256(payload)
            entry["integrity_note"] = "HMAC not available — SHA-256 hash only, not a cryptographic signature"
        self.actions.append(entry)
        return entry

    def finalize(self) -> Dict[str, Any]:
        """Mark the log complete and return the serialisable record."""
        if self.completed_at is None:
            self.log_action("shutdown", "Chain of custody finalised")
            self.completed_at = utc_now_iso()
        return self.to_dict()

    def to_dict(self) -> Dict[str, Any]:
        """Return the custody record as a plain dict."""
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "operator": self.operator,
            "hostname": self.hostname,
            "platform": self.platform,
            "command_line": self.command_line,
            "parameters": self.parameters,
            "source_files": self.source_files,
            "output_files": self.output_files,
            "actions": self.actions,
        }

    def save(self, output_path: Optional[Union[str, Path]] = None) -> Path:
        """
        Persist the chain-of-custody record as JSON.

        Parameters
        ----------
        output_path : str | Path, optional
            Destination. Defaults to ``custody_log.json`` next to the
            original ``output_path`` or in the cwd.

        Returns
        -------
        Path
            File written.
        """
        path = Path(output_path) if output_path else self.output_path
        if path is None:
            path = Path("custody_log.json")
        if path.is_dir() or str(path).endswith(("/", "\\")):
            path = path / "custody_log.json"
        if path.suffix.lower() != ".json":
            # allow callers to pass a report path — drop next to it
            if path.suffix:
                path = path.with_name("custody_log.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        record = self.finalize()
        path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
        # Avoid recursion: don't log_action again after finalize
        digest = compute_sha256(json.dumps(record, default=str))
        self.output_files.append({"path": str(path), "filename": path.name, "sha256": digest})
        return path


class ReportIntegrity:
    """Hash, optionally RSA-PSS-sign, and optionally RFC 3161-timestamp a report."""

    def __init__(
        self,
        sign: bool = False,
        timestamp: bool = False,
        tsa_url: str = DEFAULT_TSA_URL,
        private_key_path: Optional[Union[str, Path]] = None,
        private_key=None,
    ):
        self.sign = sign
        self.timestamp = timestamp
        self.tsa_url = tsa_url
        self.private_key_path = Path(private_key_path) if private_key_path else None
        self.private_key = private_key
        self.content_hash: Optional[str] = None
        self.signature: Optional[str] = None
        self.timestamp_token: Optional[str] = None
        self.timestamp_error: Optional[str] = None

    def hash_content(self, content: Union[str, bytes]) -> str:
        """Hash report bytes and cache the digest."""
        self.content_hash = compute_sha256(content)
        return self.content_hash

    def sign_hash(self, content_hash: Optional[str] = None) -> Optional[str]:
        """
        Sign the report SHA-256 with RSA-PSS.

        Parameters
        ----------
        content_hash : str, optional
            Hex digest to sign. Defaults to the cached hash.

        Returns
        -------
        Optional[str]
            Base64 signature.
        """
        if not self.sign:
            return None
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required for report signing")
        digest_hex = content_hash or self.content_hash
        if not digest_hex:
            raise ValueError("No content hash available to sign.")
        key = self.private_key or generate_rsa_key(self.private_key_path)
        self.private_key = key
        digest_bytes = bytes.fromhex(digest_hex)
        signature_bytes = key.sign(
            digest_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            utils.Prehashed(hashes.SHA256()),
        )
        self.signature = base64.b64encode(signature_bytes).decode("ascii")
        return self.signature

    def request_timestamp(self, content_hash: Optional[str] = None) -> Optional[str]:
        """
        Submit the report hash to an RFC 3161 TSA (best-effort).

        Parameters
        ----------
        content_hash : str, optional
            Hex digest.

        Returns
        -------
        Optional[str]
            Base64 timestamp token, or None on failure.
        """
        if not self.timestamp:
            return None
        if not REQUESTS_AVAILABLE:
            self.timestamp_error = "requests library not installed"
            return None
        digest = content_hash or self.content_hash
        if not digest:
            raise ValueError("No content hash available for timestamping.")
        # REPLACE the try block (lines 377–386) inside request_timestamp():

        try:
            # Build a minimal RFC 3161 TimeStampReq (ASN.1 DER)
            # Structure: SEQUENCE { version INTEGER(1), messageImprint SEQUENCE {
            #   hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING },
            #   certReq BOOLEAN TRUE }
            digest_bytes = bytes.fromhex(digest)
            # SHA-256 OID: 2.16.840.1.101.3.4.2.1
            sha256_oid = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"
            null_params = b"\x05\x00"
            alg_id = b"\x30" + bytes([len(sha256_oid) + len(null_params)]) + sha256_oid + null_params
            hash_octet = b"\x04" + bytes([len(digest_bytes)]) + digest_bytes
            msg_imprint = b"\x30" + bytes([len(alg_id) + len(hash_octet)]) + alg_id + hash_octet
            version = b"\x02\x01\x01"          # INTEGER 1
            cert_req = b"\x01\x01\xff"          # BOOLEAN TRUE
            inner = version + msg_imprint + cert_req
            ts_req = b"\x30" + bytes([len(inner)]) + inner

            response = requests.post(
                self.tsa_url,
                data=ts_req,
                headers={"Content-Type": "application/timestamp-query"},
                timeout=15,
            )
            response.raise_for_status()
            self.timestamp_token = base64.b64encode(response.content).decode("ascii")
            return self.timestamp_token
        except Exception as exc:
            self.timestamp_error = str(exc)
            return None
            response.raise_for_status()
            self.timestamp_token = base64.b64encode(response.content).decode("ascii")
            return self.timestamp_token
        except Exception as exc:
            self.timestamp_error = str(exc)
            return None

    def process(self, content: Union[str, bytes]) -> Dict[str, Any]:
        """
        Full integrity pipeline: hash → optional sign → optional timestamp.

        Parameters
        ----------
        content : str | bytes
            Final report bytes.

        Returns
        -------
        dict
            Integrity block for embedding in the report / custody log.
        """
        content_hash = self.hash_content(content)
        signature = self.sign_hash(content_hash) if self.sign else None
        ts_token = self.request_timestamp(content_hash) if self.timestamp else None
        return {
            "sha256": content_hash,
            "signed": bool(self.sign and signature),
            "signature": signature,
            "timestamped": bool(self.timestamp and ts_token),
            "timestamp_token": ts_token,
            "timestamp_error": self.timestamp_error,
            "tsa_url": self.tsa_url if self.timestamp else None,
            "generated_at": utc_now_iso(),
        }
