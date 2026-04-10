"""
ChunkVault API Client
=====================
HTTP client that wraps every ChunkVault server endpoint.

All methods raise ``requests.HTTPError`` on non-2xx responses so callers
can handle errors with a single try/except block.
"""

from __future__ import annotations

from typing import Optional

import requests


class ChunkVaultClient:
    """
    Stateful HTTP client for one ChunkVault server.

    Attributes
    ----------
    server_url:
        Base URL, e.g. ``"http://localhost:5000"``.
    token:
        JWT bearer token set after :meth:`login`.
    """

    def __init__(self, server_url: str, token: Optional[str] = None) -> None:
        self.server_url = server_url.rstrip("/")
        self.token = token
        self._session = requests.Session()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _json_headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _auth_headers(self) -> dict:
        """Headers for non-JSON (binary) requests."""
        headers: dict = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _raise(self, resp: requests.Response) -> None:
        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            # Attach server-side error message when available
            try:
                detail = resp.json().get("error", "")
                raise requests.HTTPError(
                    f"{exc} – {detail}", response=resp
                ) from exc
            except Exception:
                raise exc

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def register(self, username: str, password: str) -> dict:
        resp = self._session.post(
            f"{self.server_url}/auth/register",
            json={"username": username, "password": password},
        )
        self._raise(resp)
        return resp.json()

    def login(self, username: str, password: str) -> str:
        """Login and store the JWT token.  Returns the raw token string."""
        resp = self._session.post(
            f"{self.server_url}/auth/login",
            json={"username": username, "password": password},
        )
        self._raise(resp)
        data = resp.json()
        self.token = data["token"]
        return self.token

    # ------------------------------------------------------------------
    # Files
    # ------------------------------------------------------------------

    def list_files(self) -> list[dict]:
        resp = self._session.get(
            f"{self.server_url}/files",
            headers=self._json_headers(),
        )
        self._raise(resp)
        return resp.json()["files"]

    def create_file(self, filename: str, total_chunks: int, chunk_size: int) -> str:
        """Create a file record on the server.  Returns the file_id."""
        resp = self._session.post(
            f"{self.server_url}/files",
            json={"filename": filename, "total_chunks": total_chunks,
                  "chunk_size": chunk_size},
            headers=self._json_headers(),
        )
        self._raise(resp)
        return resp.json()["file_id"]

    def get_file_metadata(self, file_id: str) -> dict:
        resp = self._session.get(
            f"{self.server_url}/files/{file_id}",
            headers=self._json_headers(),
        )
        self._raise(resp)
        return resp.json()

    def delete_file(self, file_id: str) -> dict:
        resp = self._session.delete(
            f"{self.server_url}/files/{file_id}",
            headers=self._json_headers(),
        )
        self._raise(resp)
        return resp.json()

    # ------------------------------------------------------------------
    # Chunks
    # ------------------------------------------------------------------

    def upload_chunk(self, file_id: str, chunk_index: int,
                     encrypted_data: bytes) -> dict:
        """Upload one encrypted chunk blob.  Returns the server response dict."""
        resp = self._session.put(
            f"{self.server_url}/files/{file_id}/chunks/{chunk_index}",
            data=encrypted_data,
            headers=self._auth_headers(),
        )
        self._raise(resp)
        return resp.json()

    def download_chunk(self, file_id: str, chunk_index: int) -> bytes:
        """Download one encrypted chunk blob.  Returns raw bytes."""
        resp = self._session.get(
            f"{self.server_url}/files/{file_id}/chunks/{chunk_index}",
            headers=self._auth_headers(),
        )
        self._raise(resp)
        return resp.content

    # ------------------------------------------------------------------
    # ACL
    # ------------------------------------------------------------------

    def grant_access(self, file_id: str, username: str, role: str) -> dict:
        resp = self._session.post(
            f"{self.server_url}/files/{file_id}/acl",
            json={"username": username, "role": role},
            headers=self._json_headers(),
        )
        self._raise(resp)
        return resp.json()

    def revoke_access(self, file_id: str, username: str) -> dict:
        resp = self._session.delete(
            f"{self.server_url}/files/{file_id}/acl",
            json={"username": username},
            headers=self._json_headers(),
        )
        self._raise(resp)
        return resp.json()

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def get_audit_log(self, file_id: Optional[str] = None,
                      limit: int = 100) -> list[dict]:
        params: dict = {"limit": limit}
        if file_id:
            params["file_id"] = file_id
        resp = self._session.get(
            f"{self.server_url}/audit",
            params=params,
            headers=self._json_headers(),
        )
        self._raise(resp)
        return resp.json()["events"]


__all__ = ["ChunkVaultClient"]
