"""
ChunkVault Server
=================
Flask REST API for the ChunkVault encrypted chunk storage system.

Responsibilities:
  - User registration and JWT authentication
  - File metadata management (chunk count, ACL, timestamps)
  - Blob storage for encrypted chunks (filesystem-backed)
  - Role-based access enforcement: owner / writer / reader
  - Append-only audit log (JSONL)

Run:
    python -m server.app          # dev
    chunkvault-server             # if installed via setup.py
"""

import json
import logging
import os
import secrets
import shutil
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

import bcrypt
from flask import Flask, jsonify, request, send_file
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)

# ---------------------------------------------------------------------------
# App & storage layout
# ---------------------------------------------------------------------------

app = Flask(__name__)

BASE_DIR = Path(__file__).parent
STORAGE_DIR = BASE_DIR / "storage"
CHUNKS_DIR = STORAGE_DIR / "chunks"
METADATA_DIR = STORAGE_DIR / "metadata"
USERS_FILE = STORAGE_DIR / "users.json"
AUDIT_FILE = STORAGE_DIR / "audit.jsonl"
SECRET_FILE = STORAGE_DIR / ".jwt_secret"

# Create directories on startup
for d in (STORAGE_DIR, CHUNKS_DIR, METADATA_DIR):
    d.mkdir(parents=True, exist_ok=True)

if not USERS_FILE.exists():
    USERS_FILE.write_text(json.dumps({}))

# JWT secret: prefer env var, then persist a generated one so restarts keep tokens valid
_jwt_secret = os.environ.get("JWT_SECRET_KEY")
if not _jwt_secret:
    if SECRET_FILE.exists():
        _jwt_secret = SECRET_FILE.read_text().strip()
    else:
        _jwt_secret = secrets.token_hex(32)
        SECRET_FILE.write_text(_jwt_secret)
        SECRET_FILE.chmod(0o600)

app.config["JWT_SECRET_KEY"] = _jwt_secret
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 86400  # 24 h

jwt = JWTManager(app)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------


def _load_users() -> dict:
    return json.loads(USERS_FILE.read_text())


def _save_users(users: dict) -> None:
    USERS_FILE.write_text(json.dumps(users, indent=2))


def _load_meta(file_id: str) -> dict | None:
    p = METADATA_DIR / f"{file_id}.json"
    if not p.exists():
        return None
    return json.loads(p.read_text())


def _save_meta(file_id: str, meta: dict) -> None:
    (METADATA_DIR / f"{file_id}.json").write_text(json.dumps(meta, indent=2))


def _append_audit(event: str, username: str, *, file_id: str | None = None,
                  chunk_index: int | None = None, details: dict | None = None) -> None:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "username": username,
        "ip": request.remote_addr,
        "file_id": file_id,
        "chunk_index": chunk_index,
        "details": details or {},
    }
    with open(AUDIT_FILE, "a") as fh:
        fh.write(json.dumps(record) + "\n")


def _user_role(file_id: str, username: str) -> str | None:
    meta = _load_meta(file_id)
    if meta is None:
        return None
    return meta.get("acl", {}).get(username)


# ---------------------------------------------------------------------------
# Authorization decorator
# ---------------------------------------------------------------------------


def require_role(*roles):
    """Apply AFTER @jwt_required() so identity is available."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            username = get_jwt_identity()
            file_id = kwargs.get("file_id")

            # Admins bypass ACL checks
            users = _load_users()
            if users.get(username, {}).get("is_admin"):
                return fn(*args, **kwargs)

            role = _user_role(file_id, username)
            if role not in roles:
                _append_audit("ACCESS_DENIED", username, file_id=file_id,
                              details={"required": list(roles), "has": role})
                return jsonify({"error": "Insufficient permissions"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------


@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if not (3 <= len(username) <= 32):
        return jsonify({"error": "username must be 3–32 characters"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    users = _load_users()
    if username in users:
        return jsonify({"error": "username already exists"}), 409

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = {
        "password_hash": pw_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "is_admin": len(users) == 0,  # first registered user becomes admin
    }
    _save_users(users)
    _append_audit("USER_REGISTERED", username)
    return jsonify({"message": "registered", "username": username}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    users = _load_users()
    user = users.get(username)
    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        _append_audit("LOGIN_FAILED", username or "unknown")
        return jsonify({"error": "invalid credentials"}), 401

    token = create_access_token(identity=username)
    _append_audit("LOGIN_SUCCESS", username)
    return jsonify({"token": token, "username": username,
                    "is_admin": user.get("is_admin", False)})


# ---------------------------------------------------------------------------
# File routes
# ---------------------------------------------------------------------------


@app.route("/files", methods=["GET"])
@jwt_required()
def list_files():
    username = get_jwt_identity()
    users = _load_users()
    is_admin = users.get(username, {}).get("is_admin", False)

    result = []
    for p in METADATA_DIR.glob("*.json"):
        meta = json.loads(p.read_text())
        acl = meta.get("acl", {})
        if is_admin or username in acl:
            result.append({
                "file_id": meta["file_id"],
                "filename": meta["filename"],
                "total_chunks": meta["total_chunks"],
                "chunk_size": meta["chunk_size"],
                "created_at": meta["created_at"],
                "owner": meta["owner"],
                "role": acl.get(username, "admin" if is_admin else "none"),
            })
    return jsonify({"files": result})


@app.route("/files", methods=["POST"])
@jwt_required()
def create_file():
    username = get_jwt_identity()
    data = request.get_json(silent=True) or {}

    filename = str(data.get("filename", "")).strip()
    total_chunks = data.get("total_chunks")
    chunk_size = data.get("chunk_size")

    if not filename or total_chunks is None or chunk_size is None:
        return jsonify({"error": "filename, total_chunks, chunk_size required"}), 400
    if not isinstance(total_chunks, int) or total_chunks < 1:
        return jsonify({"error": "total_chunks must be a positive integer"}), 400
    if not isinstance(chunk_size, int) or chunk_size < 1:
        return jsonify({"error": "chunk_size must be a positive integer"}), 400

    file_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    meta = {
        "file_id": file_id,
        "filename": filename,
        "total_chunks": total_chunks,
        "chunk_size": chunk_size,
        "created_at": now,
        "updated_at": now,
        "owner": username,
        "acl": {username: "owner"},
        "chunk_status": ["missing"] * total_chunks,
    }
    (CHUNKS_DIR / file_id).mkdir(parents=True, exist_ok=True)
    _save_meta(file_id, meta)
    _append_audit("FILE_CREATED", username, file_id=file_id,
                  details={"filename": filename, "total_chunks": total_chunks})
    return jsonify({"file_id": file_id, "message": "file created"}), 201


@app.route("/files/<file_id>", methods=["GET"])
@jwt_required()
@require_role("owner", "writer", "reader")
def get_file_metadata(file_id):
    username = get_jwt_identity()
    meta = _load_meta(file_id)
    if meta is None:
        return jsonify({"error": "file not found"}), 404

    _append_audit("FILE_METADATA_READ", username, file_id=file_id)
    role = _user_role(file_id, username)
    response = {
        "file_id": meta["file_id"],
        "filename": meta["filename"],
        "total_chunks": meta["total_chunks"],
        "chunk_size": meta["chunk_size"],
        "created_at": meta["created_at"],
        "updated_at": meta.get("updated_at"),
        "owner": meta["owner"],
        "your_role": role,
        "chunks_present": sum(1 for s in meta.get("chunk_status", []) if s == "present"),
    }
    if role == "owner":
        response["acl"] = meta.get("acl", {})
    return jsonify(response)


@app.route("/files/<file_id>", methods=["DELETE"])
@jwt_required()
@require_role("owner")
def delete_file(file_id):
    username = get_jwt_identity()
    meta = _load_meta(file_id)
    if meta is None:
        return jsonify({"error": "file not found"}), 404

    chunks_dir = CHUNKS_DIR / file_id
    if chunks_dir.exists():
        shutil.rmtree(chunks_dir)
    (METADATA_DIR / f"{file_id}.json").unlink(missing_ok=True)

    _append_audit("FILE_DELETED", username, file_id=file_id,
                  details={"filename": meta["filename"]})
    return jsonify({"message": "file deleted"})


# ---------------------------------------------------------------------------
# Chunk routes
# ---------------------------------------------------------------------------


@app.route("/files/<file_id>/chunks/<int:chunk_index>", methods=["GET"])
@jwt_required()
@require_role("owner", "writer", "reader")
def download_chunk(file_id, chunk_index):
    username = get_jwt_identity()
    meta = _load_meta(file_id)
    if meta is None:
        return jsonify({"error": "file not found"}), 404

    if not (0 <= chunk_index < meta["total_chunks"]):
        return jsonify({"error": f"chunk index out of range (0–{meta['total_chunks'] - 1})"}), 400

    chunk_path = CHUNKS_DIR / file_id / f"chunk_{chunk_index:08d}.bin"
    if not chunk_path.exists():
        return jsonify({"error": "chunk not yet uploaded"}), 404

    _append_audit("CHUNK_DOWNLOADED", username, file_id=file_id, chunk_index=chunk_index)
    return send_file(chunk_path, mimetype="application/octet-stream",
                     as_attachment=True,
                     download_name=f"chunk_{chunk_index}.bin")


@app.route("/files/<file_id>/chunks/<int:chunk_index>", methods=["PUT"])
@jwt_required()
@require_role("owner", "writer")
def upload_chunk(file_id, chunk_index):
    username = get_jwt_identity()
    meta = _load_meta(file_id)
    if meta is None:
        return jsonify({"error": "file not found"}), 404

    if not (0 <= chunk_index < meta["total_chunks"]):
        return jsonify({"error": f"chunk index out of range (0–{meta['total_chunks'] - 1})"}), 400

    chunk_data = request.get_data()
    if not chunk_data:
        return jsonify({"error": "no chunk data in request body"}), 400

    chunk_path = CHUNKS_DIR / file_id / f"chunk_{chunk_index:08d}.bin"
    chunk_path.write_bytes(chunk_data)

    meta["chunk_status"][chunk_index] = "present"
    meta["updated_at"] = datetime.now(timezone.utc).isoformat()
    _save_meta(file_id, meta)

    _append_audit("CHUNK_UPLOADED", username, file_id=file_id, chunk_index=chunk_index,
                  details={"size_bytes": len(chunk_data)})
    return jsonify({"message": f"chunk {chunk_index} stored", "size": len(chunk_data)})


# ---------------------------------------------------------------------------
# ACL routes
# ---------------------------------------------------------------------------


@app.route("/files/<file_id>/acl", methods=["POST"])
@jwt_required()
@require_role("owner")
def grant_access(file_id):
    username = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    target = str(data.get("username", "")).strip()
    role = str(data.get("role", "")).strip()

    if not target or role not in ("reader", "writer", "owner"):
        return jsonify({"error": "username and role (reader/writer/owner) required"}), 400

    users = _load_users()
    if target not in users:
        return jsonify({"error": "target user does not exist"}), 404

    meta = _load_meta(file_id)
    if meta is None:
        return jsonify({"error": "file not found"}), 404

    meta["acl"][target] = role
    _save_meta(file_id, meta)
    _append_audit("ACL_GRANTED", username, file_id=file_id,
                  details={"target": target, "role": role})
    return jsonify({"message": f"granted {role} to {target}"})


@app.route("/files/<file_id>/acl", methods=["DELETE"])
@jwt_required()
@require_role("owner")
def revoke_access(file_id):
    username = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    target = str(data.get("username", "")).strip()

    if not target:
        return jsonify({"error": "username required"}), 400

    meta = _load_meta(file_id)
    if meta is None:
        return jsonify({"error": "file not found"}), 404

    if target == meta["owner"]:
        return jsonify({"error": "cannot revoke the file owner's access"}), 400

    meta["acl"].pop(target, None)
    _save_meta(file_id, meta)
    _append_audit("ACL_REVOKED", username, file_id=file_id, details={"target": target})
    return jsonify({"message": f"revoked access for {target}"})


# ---------------------------------------------------------------------------
# Audit routes
# ---------------------------------------------------------------------------


@app.route("/audit", methods=["GET"])
@jwt_required()
def get_audit_log():
    username = get_jwt_identity()
    filter_file_id = request.args.get("file_id")
    limit = min(int(request.args.get("limit", 100)), 1000)

    users = _load_users()
    is_admin = users.get(username, {}).get("is_admin", False)

    events = []
    if AUDIT_FILE.exists():
        for raw in AUDIT_FILE.read_text().splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                ev = json.loads(raw)
            except json.JSONDecodeError:
                continue

            # Non-admins only see their own events or events on files they own
            if not is_admin:
                fid = ev.get("file_id")
                if fid:
                    if _user_role(fid, username) != "owner":
                        continue
                elif ev.get("username") != username:
                    continue

            if filter_file_id and ev.get("file_id") != filter_file_id:
                continue
            events.append(ev)

    events = events[-limit:]
    _append_audit("AUDIT_LOG_READ", username,
                  details={"filter_file_id": filter_file_id, "limit": limit})
    return jsonify({"events": events, "count": len(events)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    logger.info("ChunkVault server starting on %s:%s", host, port)
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
