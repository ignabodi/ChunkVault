#!/usr/bin/env python3
"""
ChunkVault CLI
==============
Command-line interface for the ChunkVault chunk-encrypted cloud storage system.

Quick start
-----------
    chunkvault configure http://localhost:5000   # point at your server
    chunkvault register alice                    # create account
    chunkvault login alice                       # get a JWT token

    chunkvault upload report.csv                # encrypt & upload
    chunkvault list-files                        # see your files
    chunkvault download <file-id> out.csv        # decrypt & download

    # Random-access operations (no full-file download needed)
    chunkvault read-chunk  <file-id> 3                  # decrypt chunk 3
    chunkvault write-chunk <file-id> 3 new_data.bin     # replace chunk 3

    # Collaboration
    chunkvault grant-access <file-id> bob reader
    chunkvault export-key   <file-id> key_for_bob.json --role reader
    # bob runs: chunkvault import-key key_for_bob.json

    chunkvault audit --file-id <file-id>         # audit log
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
import requests

from client.api_client import ChunkVaultClient
from client.chunker import DEFAULT_CHUNK_SIZE, assemble_file, count_chunks, iter_chunks
from client.crypto import decrypt_chunk, encrypt_chunk, generate_file_key
from client.keystore import KeyStore

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path.home() / ".chunkvault" / "config.json"
_DEFAULT_SERVER = "http://localhost:5000"


def _load_config() -> dict:
    if _CONFIG_PATH.exists():
        return json.loads(_CONFIG_PATH.read_text())
    return {"server": _DEFAULT_SERVER}


def _save_config(cfg: dict) -> None:
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    _CONFIG_PATH.chmod(0o600)


def _make_client(cfg: dict) -> ChunkVaultClient:
    return ChunkVaultClient(
        server_url=cfg.get("server", _DEFAULT_SERVER),
        token=cfg.get("token"),
    )


def _err(msg: str) -> None:
    click.echo(f"Error: {msg}", err=True)
    sys.exit(1)


def _http_err(exc: requests.HTTPError) -> None:
    _err(str(exc))


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@click.group()
@click.option("--server", default=None, metavar="URL",
              help="Override server URL for this invocation.")
@click.pass_context
def cli(ctx: click.Context, server: Optional[str]) -> None:
    """ChunkVault – chunk-encrypted cloud storage with random access."""
    cfg = _load_config()
    if server:
        cfg["server"] = server
    ctx.ensure_object(dict)
    ctx.obj["config"] = cfg


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("server_url")
def configure(server_url: str) -> None:
    """Set the default server URL."""
    cfg = _load_config()
    cfg["server"] = server_url
    _save_config(cfg)
    click.echo(f"Server set to: {server_url}")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("username")
@click.password_option(help="Account password.")
@click.pass_context
def register(ctx: click.Context, username: str, password: str) -> None:
    """Create a new ChunkVault user account."""
    client = _make_client(ctx.obj["config"])
    try:
        res = client.register(username, password)
        click.echo(f"Registered: {res['username']}")
    except requests.HTTPError as exc:
        _http_err(exc)


@cli.command()
@click.argument("username")
@click.option("--password", prompt=True, hide_input=True, help="Account password.")
@click.pass_context
def login(ctx: click.Context, username: str, password: str) -> None:
    """Login and save the auth token locally."""
    cfg = ctx.obj["config"]
    client = _make_client(cfg)
    try:
        client.login(username, password)
        cfg["token"] = client.token
        cfg["username"] = username
        _save_config(cfg)
        click.echo(f"Logged in as: {username}")
    except requests.HTTPError as exc:
        _http_err(exc)


# ---------------------------------------------------------------------------
# File operations
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--chunk-size", default=DEFAULT_CHUNK_SIZE, show_default=True,
              metavar="BYTES", help="Chunk size in bytes.")
@click.pass_context
def upload(ctx: click.Context, file_path: str, chunk_size: int) -> None:
    """Encrypt a local file and upload it to ChunkVault."""
    cfg = ctx.obj["config"]
    client = _make_client(cfg)
    keystore = KeyStore()
    fp = Path(file_path)

    total = count_chunks(fp, chunk_size)
    if total == 0:
        _err("file is empty")

    click.echo(f"Uploading '{fp.name}'  ({total} × {chunk_size} B chunks)")

    try:
        file_id = client.create_file(fp.name, total, chunk_size)
        click.echo(f"File ID : {file_id}")

        file_key = generate_file_key()

        with click.progressbar(iter_chunks(fp, chunk_size), length=total,
                               label="Encrypting & uploading") as bar:
            for idx, chunk_data in bar:
                encrypted = encrypt_chunk(file_key, idx, chunk_data)
                client.upload_chunk(file_id, idx, encrypted)

        keystore.store(file_id, file_key, "owner", fp.name)
        click.echo(f"Done.  File ID: {file_id}")

    except requests.HTTPError as exc:
        _http_err(exc)


@cli.command()
@click.argument("file_id")
@click.argument("output_path", type=click.Path())
@click.pass_context
def download(ctx: click.Context, file_id: str, output_path: str) -> None:
    """Download and decrypt an entire file from ChunkVault."""
    cfg = ctx.obj["config"]
    client = _make_client(cfg)
    keystore = KeyStore()

    file_key = keystore.get_key(file_id)
    if file_key is None:
        _err(f"no decryption key found for {file_id}\n"
             "       Use 'chunkvault import-key <key_file>' first.")

    try:
        meta = client.get_file_metadata(file_id)
        total = meta["total_chunks"]
        click.echo(f"Downloading '{meta['filename']}'  ({total} chunks)")

        def _decrypted():
            for i in range(total):
                blob = client.download_chunk(file_id, i)
                yield decrypt_chunk(file_key, i, blob)

        with click.progressbar(range(total), label="Downloading & decrypting") as bar:
            chunks_iter = _decrypted()
            assemble_file(chunks_iter, output_path)
            # exhaust the progress bar
            for _ in bar:
                pass

        click.echo(f"Saved to: {output_path}")

    except requests.HTTPError as exc:
        _http_err(exc)


@cli.command("list-files")
@click.pass_context
def list_files(ctx: click.Context) -> None:
    """List files accessible to the current user."""
    client = _make_client(ctx.obj["config"])
    try:
        files = client.list_files()
    except requests.HTTPError as exc:
        _http_err(exc)

    if not files:
        click.echo("No files found.")
        return

    click.echo(
        f"{'File ID':<38}  {'Filename':<26} {'Chunks':>6}  {'Role':<8}  Owner"
    )
    click.echo("-" * 92)
    for f in files:
        click.echo(
            f"{f['file_id']:<38}  {f['filename']:<26} {f['total_chunks']:>6}"
            f"  {f['role']:<8}  {f['owner']}"
        )


@cli.command()
@click.argument("file_id")
@click.pass_context
def info(ctx: click.Context, file_id: str) -> None:
    """Show metadata for a file."""
    client = _make_client(ctx.obj["config"])
    try:
        meta = client.get_file_metadata(file_id)
        click.echo(json.dumps(meta, indent=2))
    except requests.HTTPError as exc:
        _http_err(exc)


@cli.command("delete-file")
@click.argument("file_id")
@click.confirmation_option(prompt="Delete this file permanently?")
@click.pass_context
def delete_file(ctx: click.Context, file_id: str) -> None:
    """Delete a file from ChunkVault (owner only)."""
    cfg = ctx.obj["config"]
    client = _make_client(cfg)
    keystore = KeyStore()
    try:
        res = client.delete_file(file_id)
        keystore.remove(file_id)
        click.echo(res["message"])
    except requests.HTTPError as exc:
        _http_err(exc)


# ---------------------------------------------------------------------------
# Random-access chunk operations  ← core feature
# ---------------------------------------------------------------------------


@cli.command("read-chunk")
@click.argument("file_id")
@click.argument("chunk_index", type=int)
@click.option("--output", "-o", default=None, type=click.Path(),
              help="Write decrypted bytes to this file instead of stdout.")
@click.pass_context
def read_chunk(ctx: click.Context, file_id: str, chunk_index: int,
               output: Optional[str]) -> None:
    """
    Download and decrypt a SINGLE chunk (random-access read).

    Useful for inspecting a specific slice of a large dataset without
    downloading the whole file.
    """
    cfg = ctx.obj["config"]
    client = _make_client(cfg)
    keystore = KeyStore()

    file_key = keystore.get_key(file_id)
    if file_key is None:
        _err(f"no decryption key for {file_id}")

    try:
        encrypted = client.download_chunk(file_id, chunk_index)
        plaintext = decrypt_chunk(file_key, chunk_index, encrypted)
    except requests.HTTPError as exc:
        _http_err(exc)
    except Exception as exc:
        _err(str(exc))

    if output:
        Path(output).write_bytes(plaintext)
        click.echo(f"Chunk {chunk_index} → {output}  ({len(plaintext)} B)")
    else:
        try:
            click.echo(plaintext.decode("utf-8"))
        except UnicodeDecodeError:
            click.echo(f"[Binary – {len(plaintext)} B, hex preview:]")
            click.echo(plaintext[:256].hex())


@cli.command("write-chunk")
@click.argument("file_id")
@click.argument("chunk_index", type=int)
@click.argument("data_file", type=click.Path(exists=True))
@click.pass_context
def write_chunk(ctx: click.Context, file_id: str, chunk_index: int,
                data_file: str) -> None:
    """
    Encrypt and upload a SINGLE chunk (random-access write).

    Reads replacement bytes from DATA_FILE, encrypts them, and pushes the
    updated chunk to the server – leaving all other chunks untouched.
    Requires at least writer access.
    """
    cfg = ctx.obj["config"]
    client = _make_client(cfg)
    keystore = KeyStore()

    role = keystore.get_role(file_id)
    if role is None:
        _err(f"no key found for {file_id}")
    if role == "reader":
        _err("read-only access – cannot write chunks")

    file_key = keystore.get_key(file_id)
    try:
        plaintext = Path(data_file).read_bytes()
        encrypted = encrypt_chunk(file_key, chunk_index, plaintext)
        res = client.upload_chunk(file_id, chunk_index, encrypted)
        click.echo(f"Chunk {chunk_index} updated  ({res['size']} encrypted B)")
    except requests.HTTPError as exc:
        _http_err(exc)


# ---------------------------------------------------------------------------
# ACL management
# ---------------------------------------------------------------------------


@cli.command("grant-access")
@click.argument("file_id")
@click.argument("username")
@click.argument("role", type=click.Choice(["reader", "writer", "owner"]))
@click.pass_context
def grant_access(ctx: click.Context, file_id: str, username: str, role: str) -> None:
    """Grant a user access to a file (owner only)."""
    client = _make_client(ctx.obj["config"])
    try:
        res = client.grant_access(file_id, username, role)
        click.echo(res["message"])
    except requests.HTTPError as exc:
        _http_err(exc)


@cli.command("revoke-access")
@click.argument("file_id")
@click.argument("username")
@click.pass_context
def revoke_access(ctx: click.Context, file_id: str, username: str) -> None:
    """Revoke a user's access to a file (owner only)."""
    client = _make_client(ctx.obj["config"])
    try:
        res = client.revoke_access(file_id, username)
        click.echo(res["message"])
    except requests.HTTPError as exc:
        _http_err(exc)


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------


@cli.command("export-key")
@click.argument("file_id")
@click.argument("output_file", type=click.Path())
@click.option("--role", default="reader",
              type=click.Choice(["reader", "writer"]),
              help="Role to embed in the exported key package.")
@click.pass_context
def export_key(ctx: click.Context, file_id: str, output_file: str,
               role: str) -> None:
    """Export a key package for sharing with a collaborator."""
    keystore = KeyStore()
    my_role = keystore.get_role(file_id)
    if my_role is None:
        _err(f"no key stored for {file_id}")
    if my_role == "reader" and role == "writer":
        _err("you only have reader access – cannot export a writer key")

    try:
        package = keystore.export_package(file_id, role)
        Path(output_file).write_text(json.dumps(package, indent=2))
        click.echo(f"Key exported to '{output_file}'  (role: {role})")
    except Exception as exc:
        _err(str(exc))


@cli.command("import-key")
@click.argument("key_file", type=click.Path(exists=True))
@click.pass_context
def import_key(ctx: click.Context, key_file: str) -> None:
    """Import a key package shared by a collaborator."""
    keystore = KeyStore()
    try:
        package = json.loads(Path(key_file).read_text())
        keystore.import_package(package)
        click.echo(
            f"Key imported  file_id={package['file_id']}  role={package.get('role', '?')}"
        )
    except Exception as exc:
        _err(str(exc))


@cli.command("list-keys")
def list_keys() -> None:
    """Show all encryption keys stored in the local keystore."""
    keystore = KeyStore()
    entries = keystore.list_entries()
    if not entries:
        click.echo("No keys in local keystore.")
        return
    click.echo(f"{'File ID':<38}  {'Role':<8}  Filename")
    click.echo("-" * 70)
    for e in entries:
        click.echo(f"{e['file_id']:<38}  {e['role']:<8}  {e['filename']}")


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--file-id", default=None, help="Filter events by file ID.")
@click.option("--limit", default=50, show_default=True,
              help="Maximum number of events to display.")
@click.pass_context
def audit(ctx: click.Context, file_id: Optional[str], limit: int) -> None:
    """Display the audit log."""
    client = _make_client(ctx.obj["config"])
    try:
        events = client.get_audit_log(file_id=file_id, limit=limit)
    except requests.HTTPError as exc:
        _http_err(exc)

    if not events:
        click.echo("No audit events found.")
        return

    for ev in events:
        ts = ev.get("timestamp", "")[:19].replace("T", " ")
        event = ev.get("event", "")
        user = ev.get("username", "")
        fid = ev.get("file_id") or ""
        ci = ev.get("chunk_index")
        fid_str = f" [{fid[:8]}…]" if fid else ""
        ci_str = f" chunk={ci}" if ci is not None else ""
        click.echo(f"{ts}  {event:<32}  {user:<20}{fid_str}{ci_str}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    cli()
