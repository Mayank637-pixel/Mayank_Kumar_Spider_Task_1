#!/usr/bin/env python3
"""
Generate a seed corpus for AFL++ fuzzing of the license validator.

The seed is a structurally valid license blob (correct CRC, proper version,
well-formed chunks) so AFL++ starts from a meaningful base and can reach deep
parsing logic faster.  The signature MAC is intentionally zeroed — it won't
pass crypto verification, but that's fine: AFL++ will mutate from here.

Usage: python3 gen_corpus.py
Output: corpus/seed01.bin
"""

import os
import struct


def crc32(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if (crc & 1) else 0)
    return (~crc) & 0xFFFFFFFF


def u16be(n: int) -> bytes:
    return struct.pack(">H", n)


def u32be(n: int) -> bytes:
    return struct.pack(">I", n)


def tlv(chunk_type: int, payload: bytes) -> bytes:
    return bytes([chunk_type]) + u16be(len(payload)) + payload


def build_seed() -> bytes:
    buf = bytearray()
    buf += b"\x00" * 4          # CRC placeholder (bytes 0-3)
    buf += bytes([0x01, 0x00])  # version 1.0
    buf += bytes([0x00, 0x00])  # flags

    buf += tlv(0x01, b"SPJLabs")               # OWNER
    buf += tlv(0x02, u32be(2))                 # LEVEL = 2
    buf += tlv(0x03, u32be(1893456000))        # EXPIRY = 2030-01-01
    buf += tlv(0x06, b"BASIC,ADVANCED")        # FEATURES
    buf += tlv(0x09, b"HWID-DEADBEEF")         # HWID
    buf += tlv(0x04, b"\x00" * 256)            # SIGNATURE (zeroed MAC)
    buf += tlv(0x42, b"A"*55)	
    # Patch CRC over bytes 4..end
    payload_crc = crc32(bytes(buf[4:]))
    struct.pack_into(">I", buf, 0, payload_crc)

    return bytes(buf)


if __name__ == "__main__":
    os.makedirs("corpus", exist_ok=True)
    seed = build_seed()
    out = "corpus/seed01.bin"
    with open(out, "wb") as fh:
        fh.write(seed)
    print(f"[+] {out}  ({len(seed)} bytes)")
