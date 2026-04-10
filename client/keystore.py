"""
ChunkVault KeyStore
===================
Manages per-file encryption keys on the local client machine.

Keys are stored in ``~/.chunkvault/keystore.json`` (mode 0600).  Each entry
records the base64-encoded 256-bit file master key together with the user's
assigned role and the original filename (for display purposes).

The keystore never leaves the client device.  Sharing a key with a
collaborator is an explicit, manual step:  export a *key package* (a small
JSON dict) and out-of-band it to your teammate who then imports it.

Roles
-----
owner  – can read and write all chunks, manage the ACL, delete the file
writer – can read and write chunks
reader – can only read chunks  (the CLI refuses write operations locally
         before even contacting the server)
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Optional

_DEFAULT_PATH = Path.home() / ".chunkvault" / "keystore.json"


class KeyStore:
    """
    Thin JSON-backed store for file encryption keys.

    Thread safety: not thread-safe (single-user CLI tool).
    """

    def __init__(self, path: Path = _DEFAULT_PATH) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write({})
        # Ensure restrictive permissions (owner r/w only)
        self.path.chmod(0o600)

    # ------------------------------------------------------------------
    # Internal I/O
    # ------------------------------------------------------------------

    def _read(self) -> dict:
        return json.loads(self.path.read_text())

    def _write(self, data: dict) -> None:
        self.path.write_text(json.dumps(data, indent=2))
        self.path.chmod(0o600)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def store(self, file_id: str, file_key: bytes, role: str,
              filename: str = "") -> None:
        """Add or overwrite the entry for *file_id*."""
        data = self._read()
        data[file_id] = {
            "key": base64.b64encode(file_key).decode(),
            "role": role,
            "filename": filename,
        }
        self._write(data)

    def get_key(self, file_id: str) -> Optional[bytes]:
        """Return the raw key bytes, or *None* if not found."""
        entry = self._read().get(file_id)
        if entry is None:
            return None
        return base64.b64decode(entry["key"])

    def get_role(self, file_id: str) -> Optional[str]:
        """Return the stored role string, or *None* if not found."""
        entry = self._read().get(file_id)
        return entry["role"] if entry else None

    def get_filename(self, file_id: str) -> str:
        entry = self._read().get(file_id)
        return entry.get("filename", "") if entry else ""

    def remove(self, file_id: str) -> bool:
        """Delete the key entry for *file_id*.  Returns True if it existed."""
        data = self._read()
        if file_id not in data:
            return False
        del data[file_id]
        self._write(data)
        return True

    def list_entries(self) -> list[dict]:
        """Return a list of summary dicts (no raw key bytes)."""
        return [
            {"file_id": fid, "role": v["role"], "filename": v.get("filename", "")}
            for fid, v in self._read().items()
        ]

    def export_package(self, file_id: str, export_role: str) -> dict:
        """
        Build a *key package* dict suitable for sharing with a collaborator.

        *export_role* should be ``"reader"`` or ``"writer"`` – the exported
        package will carry this role regardless of the caller's own role.
        The caller must be either an owner or writer to export for writing.
        """
        key = self.get_key(file_id)
        if key is None:
            raise KeyError(f"No key stored for file_id={file_id!r}")
        if export_role not in ("reader", "writer"):
            raise ValueError("export_role must be 'reader' or 'writer'")
        return {
            "file_id": file_id,
            "key": base64.b64encode(key).decode(),
            "role": export_role,
        }

    def import_package(self, package: dict, filename: str = "") -> None:
        """Store a key received from a collaborator."""
        required = {"file_id", "key", "role"}
        missing = required - package.keys()
        if missing:
            raise ValueError(f"Key package missing fields: {missing}")
        file_key = base64.b64decode(package["key"])
        self.store(package["file_id"], file_key, package["role"], filename)


__all__ = ["KeyStore"]
