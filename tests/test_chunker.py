"""
Tests for client.chunker
========================
Covers:
  - count_chunks arithmetic (exact multiples, remainders, empty files)
  - iter_chunks yields correct data in order
  - assemble_file produces the original file byte-for-byte
  - read_chunk for random access
  - patch_chunk overwrites only the targeted slice
  - Full round-trip: split → reassemble → compare
"""

import os
import tempfile
from pathlib import Path

import pytest

from client.chunker import (
    DEFAULT_CHUNK_SIZE,
    assemble_file,
    count_chunks,
    iter_chunks,
    patch_chunk,
    read_chunk,
)

CHUNK = 64  # small chunk size for fast tests


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tmp_file(size: int) -> tuple[Path, bytes]:
    """Create a temporary file of *size* random bytes.  Returns (path, content)."""
    data = os.urandom(size)
    tmp = Path(tempfile.mktemp())
    tmp.write_bytes(data)
    return tmp, data


# ---------------------------------------------------------------------------
# count_chunks
# ---------------------------------------------------------------------------


class TestCountChunks:
    def test_exact_multiple(self, tmp_path):
        p = tmp_path / "f"
        p.write_bytes(b"x" * (CHUNK * 4))
        assert count_chunks(p, CHUNK) == 4

    def test_with_remainder(self, tmp_path):
        p = tmp_path / "f"
        p.write_bytes(b"x" * (CHUNK * 3 + 1))
        assert count_chunks(p, CHUNK) == 4

    def test_single_chunk(self, tmp_path):
        p = tmp_path / "f"
        p.write_bytes(b"x" * (CHUNK - 1))
        assert count_chunks(p, CHUNK) == 1

    def test_empty_file(self, tmp_path):
        p = tmp_path / "f"
        p.write_bytes(b"")
        assert count_chunks(p, CHUNK) == 0

    def test_default_chunk_size(self, tmp_path):
        p = tmp_path / "f"
        p.write_bytes(b"x" * DEFAULT_CHUNK_SIZE)
        assert count_chunks(p) == 1


# ---------------------------------------------------------------------------
# iter_chunks
# ---------------------------------------------------------------------------


class TestIterChunks:
    def test_indices_are_sequential(self, tmp_path):
        p, _ = _tmp_file(CHUNK * 5)
        try:
            indices = [i for i, _ in iter_chunks(p, CHUNK)]
            assert indices == list(range(5))
        finally:
            p.unlink()

    def test_data_matches_file(self, tmp_path):
        p, data = _tmp_file(CHUNK * 3 + 7)
        try:
            reassembled = b"".join(c for _, c in iter_chunks(p, CHUNK))
            assert reassembled == data
        finally:
            p.unlink()

    def test_last_chunk_may_be_smaller(self, tmp_path):
        p, _ = _tmp_file(CHUNK + 10)
        try:
            chunks = list(iter_chunks(p, CHUNK))
            assert len(chunks[0][1]) == CHUNK
            assert len(chunks[1][1]) == 10
        finally:
            p.unlink()


# ---------------------------------------------------------------------------
# assemble_file
# ---------------------------------------------------------------------------


class TestAssembleFile:
    def test_basic(self, tmp_path):
        data = os.urandom(CHUNK * 3)
        out = tmp_path / "out"
        assemble_file(iter([data[:CHUNK], data[CHUNK:CHUNK*2], data[CHUNK*2:]]), out)
        assert out.read_bytes() == data

    def test_creates_parent_directory(self, tmp_path):
        out = tmp_path / "nested" / "dir" / "file"
        assemble_file(iter([b"hello"]), out)
        assert out.read_bytes() == b"hello"

    def test_returns_byte_count(self, tmp_path):
        out = tmp_path / "out"
        n = assemble_file(iter([b"abc", b"de"]), out)
        assert n == 5


# ---------------------------------------------------------------------------
# read_chunk  (random access)
# ---------------------------------------------------------------------------


class TestReadChunk:
    def test_reads_correct_slice(self, tmp_path):
        data = bytes(range(256)) * 2          # 512 B
        p = tmp_path / "f"
        p.write_bytes(data)
        chunk0 = read_chunk(p, 0, CHUNK)
        chunk1 = read_chunk(p, 1, CHUNK)
        assert chunk0 == data[:CHUNK]
        assert chunk1 == data[CHUNK:CHUNK*2]

    def test_out_of_range_raises(self, tmp_path):
        p = tmp_path / "f"
        p.write_bytes(b"x" * CHUNK)
        with pytest.raises(IndexError):
            read_chunk(p, 99, CHUNK)


# ---------------------------------------------------------------------------
# patch_chunk  (random-access write)
# ---------------------------------------------------------------------------


class TestPatchChunk:
    def test_overwrites_only_target(self, tmp_path):
        original = b"A" * CHUNK + b"B" * CHUNK + b"C" * CHUNK
        p = tmp_path / "f"
        p.write_bytes(original)

        replacement = b"Z" * CHUNK
        patch_chunk(p, 1, replacement, CHUNK)

        result = p.read_bytes()
        assert result[:CHUNK] == b"A" * CHUNK
        assert result[CHUNK:CHUNK*2] == b"Z" * CHUNK
        assert result[CHUNK*2:] == b"C" * CHUNK


# ---------------------------------------------------------------------------
# Full split → encrypt → decrypt → assemble round-trip
# (integration-style, no network)
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_split_and_reassemble(self, tmp_path):
        p, original = _tmp_file(CHUNK * 7 + 33)
        out = tmp_path / "recovered"
        try:
            chunks = [data for _, data in iter_chunks(p, CHUNK)]
            assemble_file(iter(chunks), out)
            assert out.read_bytes() == original
        finally:
            p.unlink()
