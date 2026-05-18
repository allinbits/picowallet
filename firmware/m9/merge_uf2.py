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

# Pico 2 flash range. picotool tags blocks at the end of an idealized
# 16-MB region (0x10ffff00) for metadata; those land outside our 4 MB
# chip and we strip them in the merger to avoid both picotool's
# overlap rejection and its family-ID confusion when two such trailer
# blocks appear from two component UF2s.
PICO2_FLASH_BASE = 0x10000000
PICO2_FLASH_END  = 0x10400000   # exclusive


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


def filter_and_dedupe(blocks):
    """Keep only blocks whose targetAddr falls inside the chip's actual
    flash region (PICO2_FLASH_BASE..PICO2_FLASH_END), then drop any
    block whose targetAddr was already claimed by an earlier block.

    The out-of-range filter strips the embedded_end_block trailers that
    picotool emits at 0x10ffff00 -- harmless in a single-image .uf2 but
    a source of overlap errors + family-ID detection bugs when two
    component images each carry one.
    """
    out = []
    seen = set()
    dropped_oor = 0
    dropped_dup = 0
    for b in blocks:
        addr = struct.unpack_from("<I", b, 12)[0]
        if addr < PICO2_FLASH_BASE or addr >= PICO2_FLASH_END:
            dropped_oor += 1
            continue
        if addr in seen:
            dropped_dup += 1
            continue
        seen.add(addr)
        out.append(b)
    return out, dropped_oor, dropped_dup


def main():
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    out = sys.argv[1]
    blocks = []
    for inp in sys.argv[2:]:
        blocks.extend(read_blocks(inp))
    blocks, dropped_oor, dropped_dup = filter_and_dedupe(blocks)
    write_blocks(out, blocks)
    msg = (f"merged {len(blocks)} blocks "
           f"({', '.join(sys.argv[2:])}) -> {out}")
    if dropped_oor or dropped_dup:
        msg += (f" (stripped {dropped_oor} out-of-flash + "
                f"{dropped_dup} duplicate block(s))")
    print(msg)


if __name__ == "__main__":
    main()
