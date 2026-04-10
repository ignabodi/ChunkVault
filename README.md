# ChunkVault
## Authors: Santiago Escobar (ywq8ms), Daniel Jimenez-Palacios (rcx2ya), Maryam Younis (ysx7nx)
## CS 4740 Final Project

Byte-sized encryption for data stored on the cloud. Allows for efficient random-access reads and writes to large encrypted datasets by splitting files into fixed-size chunks — only the target chunk needs to be decrypted, not the entire file.

---

## Setup

**Requirements:** Python 3.11+

```bash
pip install -e .
```

---

## Running the Server

Port 5000 is often taken on macOS (AirPlay Receiver). Use port 5001:

```bash
PORT=5001 python -m server.app &
```

Point the CLI at it:

```bash
python -m client.cli configure http://localhost:5001
```

---

## Usage

### 1. Create an account and login

```bash
python -m client.cli register <username>   # password must be 8+ characters
python -m client.cli login <username>
```

The first registered user automatically becomes admin.

### 2. Upload a file

```bash
python -m client.cli upload path/to/file.csv
```

The file is split into 1 MB chunks, each encrypted independently with AES-256-GCM before being sent to the server. The server **never sees plaintext**.

### 3. List your files

```bash
python -m client.cli list-files
```

### 4. Download and decrypt a full file

```bash
python -m client.cli download <FILE_ID> output.csv
```

### 5. Random-access read (core feature)

Decrypt and view a single chunk without downloading the whole file:

```bash
python -m client.cli read-chunk <FILE_ID> 0
```

Optionally save it to a file:

```bash
python -m client.cli read-chunk <FILE_ID> 0 --output chunk0.bin
```

### 6. Random-access write (core feature)

Replace a single chunk without touching the rest of the file:

```bash
python -m client.cli write-chunk <FILE_ID> <CHUNK_INDEX> new_data.bin
```

### 7. View file metadata

```bash
python -m client.cli info <FILE_ID>
```

### 8. Delete a file

```bash
python -m client.cli delete-file <FILE_ID>
```

---

## Collaboration & Key Sharing

Keys never leave the client automatically. To share access with a collaborator:

```bash
# Grant server-side permission
python -m client.cli grant-access <FILE_ID> bob reader   # or: writer, owner

# Export a key package to share out-of-band (e.g. email, USB)
python -m client.cli export-key <FILE_ID> key_for_bob.json --role reader
```

Bob then imports it on his machine:

```bash
python -m client.cli import-key key_for_bob.json
python -m client.cli read-chunk <FILE_ID> 0
```

To revoke access:

```bash
python -m client.cli revoke-access <FILE_ID> bob
```

---

## Audit Log

Every read, write, login, and ACL change is recorded server-side:

```bash
python -m client.cli audit                      # your events
python -m client.cli audit --file-id <FILE_ID>  # events for one file
python -m client.cli audit --limit 200
```

---

## Running the Tests

No server needed:

```bash
python -m pytest tests/ -v
```

30 tests covering:
- AES-256-GCM encrypt/decrypt round-trips
- Cross-chunk ciphertext replay attack prevention (AAD binding)
- Tamper detection
- File splitting, assembly, and random-access read/write

---

## Project Structure

```
chunkvault/
├── server/
│   └── app.py          — Flask REST API (auth, files, chunks, ACL, audit log)
├── client/
│   ├── crypto.py       — AES-256-GCM per-chunk encryption + HKDF key derivation
│   ├── chunker.py      — File splitting, assembly, random-access read/write
│   ├── keystore.py     — Local encrypted key store (~/.chunkvault/)
│   ├── api_client.py   — HTTP client for all server endpoints
│   └── cli.py          — Command-line interface
└── tests/
    ├── test_crypto.py
    └── test_chunker.py
```

