"""
ChunkVault Chunker
==================
Utilities for splitting a file into fixed-size chunks and reassembling them.

The key enabler for random access:  each chunk is a self-contained, opaque
blob that can be read, written, or replaced independently of every other
chunk.  The on-disk layout is:

    chunk 0:  bytes [0,          chunk_size)
    chunk 1:  bytes [chunk_size, 2*chunk_size)
    ...
    chunk N:  bytes [N*chunk_size, EOF)   ← may be smaller than chunk_size

None of the functions here do any encryption – that is handled by
:mod:`client.crypto`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Generator, Iterator

DEFAULT_CHUNK_SIZE: int = 1024 * 1024  # 1 MiB


# ---------------------------------------------------------------------------
# Reading helpers
# ---------------------------------------------------------------------------


def count_chunks(file_path: str | Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> int:
    """Return the number of chunks a file would be split into."""
    size = Path(file_path).stat().st_size
    if size == 0:
        return 0
    return (size + chunk_size - 1) // chunk_size


def iter_chunks(
    file_path: str | Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Generator[tuple[int, bytes], None, None]:
    """
    Yield ``(chunk_index, chunk_bytes)`` tuples for every chunk in a file.

    Reads sequentially – efficient for initial upload.
    """
    with open(file_path, "rb") as fh:
        idx = 0
        while True:
            data = fh.read(chunk_size)
            if not data:
                break
            yield idx, data
            idx += 1


def read_chunk(
    file_path: str | Path,
    chunk_index: int,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    """
    Read a single chunk from a local file without touching the rest.

    This is the random-access counterpart used when a collaborator wants to
    inspect or update a specific slice of a large dataset.
    """
    offset = chunk_index * chunk_size
    with open(file_path, "rb") as fh:
        fh.seek(offset)
        data = fh.read(chunk_size)
    if not data:
        raise IndexError(
            f"chunk {chunk_index} is beyond end of file (offset {offset})"
        )
    return data


# ---------------------------------------------------------------------------
# Writing helpers
# ---------------------------------------------------------------------------


def assemble_file(chunks: Iterator[bytes], output_path: str | Path) -> int:
    """
    Write an ordered sequence of chunk bytes to *output_path*.

    Returns the total number of bytes written.  The parent directory is
    created if it does not exist.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with open(output_path, "wb") as fh:
        for chunk in chunks:
            fh.write(chunk)
            total += len(chunk)
    return total


def patch_chunk(
    file_path: str | Path,
    chunk_index: int,
    data: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """
    Overwrite a single chunk in an existing local file.

    The caller is responsible for ensuring *data* is the same size as the
    original chunk (or the last chunk of the file, which may be smaller).
    """
    offset = chunk_index * chunk_size
    with open(file_path, "r+b") as fh:
        fh.seek(offset)
        fh.write(data)


__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "count_chunks",
    "iter_chunks",
    "read_chunk",
    "assemble_file",
    "patch_chunk",
]
