"""Read the GNU build ID of an ELF file (enough ELF to find PT_NOTE / SHT_NOTE)."""

from __future__ import annotations

import hashlib
import struct

NT_GNU_BUILD_ID = 3


def _notes(data: bytes, off: int, size: int, end: str):
    pos, stop = off, off + size
    while pos + 12 <= stop:
        namesz, descsz, ntype = struct.unpack_from(end + "III", data, pos)
        pos += 12
        name = data[pos:pos + namesz].rstrip(b"\0")
        pos += (namesz + 3) & ~3
        desc = data[pos:pos + descsz]
        pos += (descsz + 3) & ~3
        yield name, ntype, desc


def build_id(data: bytes) -> str | None:
    if data[:4] != b"\x7fELF" or len(data) < 64:
        return None
    is64 = data[4] == 2
    end = "<" if data[5] == 1 else ">"
    if is64:
        phoff, shoff = struct.unpack_from(end + "QQ", data, 0x20)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(end + "HHHH", data, 0x36)
    else:
        phoff, shoff = struct.unpack_from(end + "II", data, 0x1C)
        phentsize, phnum, shentsize, shnum = struct.unpack_from(end + "HHHH", data, 0x2A)
    for i in range(phnum):
        p = phoff + i * phentsize
        if p + phentsize > len(data):
            break
        ptype = struct.unpack_from(end + "I", data, p)[0]
        if ptype != 4:  # PT_NOTE
            continue
        if is64:
            off, _, _, filesz = struct.unpack_from(end + "QQQQ", data, p + 8)
        else:
            off, _, _, filesz = struct.unpack_from(end + "IIII", data, p + 4)
        for name, ntype, desc in _notes(data, off, filesz, end):
            if name == b"GNU" and ntype == NT_GNU_BUILD_ID:
                return desc.hex()
    for i in range(shnum):  # fall back to section headers
        s = shoff + i * shentsize
        if s + shentsize > len(data):
            break
        stype = struct.unpack_from(end + "I", data, s + 4)[0]
        if stype != 7:  # SHT_NOTE
            continue
        if is64:
            off, size = struct.unpack_from(end + "QQ", data, s + 0x18)
        else:
            off, size = struct.unpack_from(end + "II", data, s + 0x10)
        for name, ntype, desc in _notes(data, off, size, end):
            if name == b"GNU" and ntype == NT_GNU_BUILD_ID:
                return desc.hex()
    return None


def identify(path: str) -> dict:
    """sha256 and build ID of a file (path may be a /proc/<pid>/map_files entry)."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return {"error": f"{type(e).__name__}: {e.strerror}"}
    return {"sha256": hashlib.sha256(data).hexdigest(), "build_id": build_id(data), "size": len(data)}
