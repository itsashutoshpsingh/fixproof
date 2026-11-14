import struct

from fixproof.elf import build_id, identify


def make_elf(bid: bytes) -> bytes:
    """A minimal 64-bit little-endian ELF with one PT_NOTE holding a GNU build ID."""
    note = struct.pack("<III", 4, len(bid), 3) + b"GNU\0" + bid
    ehdr_size, phdr_size = 64, 56
    phoff = ehdr_size
    note_off = phoff + phdr_size
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, phoff, 0, 0, ehdr_size, phdr_size, 1, 64, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 4, 4, note_off, 0, 0, len(note), len(note), 4)
    return ehdr + phdr + note


def test_build_id_from_pt_note():
    bid = bytes(range(20))
    assert build_id(make_elf(bid)) == bid.hex()


def test_not_elf():
    assert build_id(b"#!/bin/sh\necho hi\n") is None


def test_identify_reports_hash_and_missing(tmp_path):
    p = tmp_path / "lib.so"
    p.write_bytes(make_elf(b"\xaa" * 20))
    info = identify(str(p))
    assert info["build_id"] == "aa" * 20 and len(info["sha256"]) == 64
    assert "error" in identify(str(tmp_path / "missing"))
