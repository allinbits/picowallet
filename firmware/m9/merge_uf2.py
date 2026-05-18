#!/usr/bin/env python3
"""Merge multiple UF2 files into one, renumbering blocks.

UF2 blocks are 512 bytes each, self-addressing (each carries its own
target flash address), so naive concatenation almost works -- except
each input UF2 sets blockNo/numBlocks relative to its own count. The
bootrom (and the host-side USB MSC driver) may eject after seeing
"all" blocks of the first image and never process the second.

This script:
  1. Reads each input UF2 as a stream of 512-byte blocks
  2. Concatenates them in order
  3. Rewrites blockNo (0..N-1) and numBlocks (=N) across the full set
  4. Preserves familyID, flags, targetAddr, payloadSize, and data
  5. Writes the result to a single output .uf2

Usage:
  merge_uf2.py <out.uf2> <in1.uf2> <in2.uf2> [...]
"""

import struct
import sys

UF2_BLOCK_SIZE = 512
MAGIC_START0   = 0x0A324655    # 'UF2\n'
MAGIC_START1   = 0x9E5D5157
MAGIC_END      = 0x0AB16F30


def read_blocks(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) % UF2_BLOCK_SIZE != 0:
        raise SystemExit(
            f"{path}: size {len(data)} not a multiple of {UF2_BLOCK_SIZE}")
    blocks = []
    for i in range(0, len(data), UF2_BLOCK_SIZE):
        b = bytearray(data[i:i + UF2_BLOCK_SIZE])
        m0, m1 = struct.unpack_from("<II", b, 0)
        me = struct.unpack_from("<I", b, 508)[0]
        if m0 != MAGIC_START0 or m1 != MAGIC_START1 or me != MAGIC_END:
            raise SystemExit(
                f"{path}: block {i // UF2_BLOCK_SIZE} has bad magic "
                f"(0x{m0:08x}/0x{m1:08x}/0x{me:08x})")
        blocks.append(b)
    return blocks


def write_blocks(path, blocks):
    total = len(blocks)
    for i, block in enumerate(blocks):
        # blockNo at offset 20, numBlocks at offset 24 (little-endian u32)
        struct.pack_into("<II", block, 20, i, total)
    with open(path, "wb") as f:
        for b in blocks:
            f.write(b)


def main():
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    out = sys.argv[1]
    blocks = []
    for inp in sys.argv[2:]:
        blocks.extend(read_blocks(inp))
    write_blocks(out, blocks)
    print(f"merged {len(blocks)} blocks "
          f"({', '.join(sys.argv[2:])}) -> {out}")


if __name__ == "__main__":
    main()
