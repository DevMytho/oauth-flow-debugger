"""Generate a 1024x1024 RGBA app icon: emerald ring + center dot on dark zinc,
evoking the OAuth logo. Pure stdlib (zlib/struct), no PIL required."""

import struct
import zlib

SIZE = 1024
CX = CY = SIZE / 2
R_OUTER = 380
R_INNER = 265
R_DOT = 95
BG = (24, 24, 27, 255)        # zinc-900
RING = (16, 185, 129, 255)    # emerald-500
DOT = (103, 232, 249, 255)    # cyan-300 accent


def pixel(x: float, y: float):
    d = ((x - CX) ** 2 + (y - CY) ** 2) ** 0.5
    if d <= R_DOT:
        return DOT
    if R_INNER <= d <= R_OUTER:
        return RING
    return BG


def chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


raw = bytearray()
for y in range(SIZE):
    raw.append(0)  # filter: none
    for x in range(SIZE):
        raw.extend(pixel(x + 0.5, y + 0.5))

png = (
    b"\x89PNG\r\n\x1a\n"
    + chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0))
    + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    + chunk(b"IEND", b"")
)

with open("app-icon.png", "wb") as f:
    f.write(png)
print(f"wrote app-icon.png ({len(png)} bytes)")
