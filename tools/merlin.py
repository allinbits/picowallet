"""Pure-Python Keccak-f[1600] / STROBE-128 / Merlin transcripts.

Mirrors firmware/src/os/crypto/{keccak,strobe,merlin}.c byte-for-byte so
the host-side test harness can drive cometbft's SecretConnection handshake
through the device without depending on the (Rust-based) `merlin` package.

Verified by `python -m tools.merlin selftest` against the same canonical
test vector the C side passes.
"""

from __future__ import annotations
import struct


# ---------- Keccak-f[1600] ---------------------------------------------------

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_RHO = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
_PI  = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]
_MASK64 = (1 << 64) - 1

def _rotl(x, n):
    return ((x << n) | (x >> (64 - n))) & _MASK64

def keccak_f1600(s):
    for rnd in range(24):
        # Theta
        C = [s[x] ^ s[x+5] ^ s[x+10] ^ s[x+15] ^ s[x+20] for x in range(5)]
        D = [C[(x+4)%5] ^ _rotl(C[(x+1)%5], 1) for x in range(5)]
        for i in range(25):
            s[i] ^= D[i % 5]
        # Rho + Pi
        prev = s[1]
        for t in range(24):
            tmp = s[_PI[t]]
            s[_PI[t]] = _rotl(prev, _RHO[t])
            prev = tmp
        # Chi
        for y in range(0, 25, 5):
            row = s[y:y+5]
            for x in range(5):
                s[y+x] = row[x] ^ ((~row[(x+1)%5]) & row[(x+2)%5]) & _MASK64
        # Iota
        s[0] ^= _KECCAK_RC[rnd]


# ---------- STROBE-128 (AD / META_AD / PRF subset) ---------------------------

_FLAG_I = 1 << 0
_FLAG_A = 1 << 1
_FLAG_C = 1 << 2
_FLAG_M = 1 << 4
_R_INIT = 168


class Strobe:
    def __init__(self, proto: bytes):
        self.state = [0] * 25
        self.pos = 0
        self.pos_begin = 0
        self.r = _R_INIT
        self.cur_flags = 0
        self.initialized = False

        domain = bytes([1, self.r, 1, 0, 1, 12*8]) + b"STROBEv1.0.2"
        self._duplex(bytearray(domain), c_before=False, force_f=True)
        self.r -= 2
        self.initialized = True
        self._operate(_FLAG_A | _FLAG_M, bytearray(proto), more=False)

    def _state_bytes(self):
        return bytearray(b"".join(struct.pack("<Q", lane) for lane in self.state))

    def _set_state_bytes(self, b: bytearray):
        for i in range(25):
            (self.state[i],) = struct.unpack_from("<Q", b, i * 8)

    def _run_f(self):
        b = self._state_bytes()
        if self.initialized:
            b[self.pos]      ^= self.pos_begin & 0xff
            b[self.pos + 1]  ^= 0x04
            b[self.r + 1]    ^= 0x80
        self._set_state_bytes(b)
        keccak_f1600(self.state)
        self.pos = 0
        self.pos_begin = 0

    def _duplex(self, data: bytearray, c_before: bool, force_f: bool):
        b = self._state_bytes()
        dpos = 0
        n = len(data)
        while dpos < n:
            avail = self.r - self.pos
            take = min(n - dpos, avail)
            if c_before:
                for i in range(take):
                    data[dpos + i] ^= b[self.pos + i]
            for i in range(take):
                b[self.pos + i] ^= data[dpos + i]
            self.pos += take
            dpos += take
            if self.pos == self.r:
                self._set_state_bytes(b)
                self._run_f()
                b = self._state_bytes()
        self._set_state_bytes(b)
        if force_f and self.pos != 0:
            self._run_f()

    def _begin_op(self, flags: int):
        old_begin = self.pos_begin & 0xff
        self.pos_begin = self.pos + 1
        op = bytearray([old_begin, flags])
        force_f = bool(flags & _FLAG_C)
        self._duplex(op, c_before=False, force_f=force_f)

    def _operate(self, flags: int, data: bytearray, more: bool):
        if not more:
            self._begin_op(flags)
            self.cur_flags = flags
        c_before = bool(flags & _FLAG_C)
        self._duplex(data, c_before=c_before, force_f=False)

    def ad(self, data: bytes, more: bool = False):
        self._operate(_FLAG_A, bytearray(data), more)

    def meta_ad(self, data: bytes, more: bool = False):
        self._operate(_FLAG_A | _FLAG_M, bytearray(data), more)

    def prf(self, n: int) -> bytes:
        buf = bytearray(n)
        self._operate(_FLAG_I | _FLAG_A | _FLAG_C, buf, more=False)
        return bytes(buf)


# ---------- Merlin transcripts -----------------------------------------------

class Transcript:
    def __init__(self, app_label: bytes):
        self.s = Strobe(b"Merlin v1.0")
        self.append(b"dom-sep", app_label)

    def append(self, label: bytes, msg: bytes):
        sz = struct.pack("<I", len(msg))
        self.s.meta_ad(label, more=False)
        self.s.meta_ad(sz, more=True)
        self.s.ad(msg, more=False)

    def challenge(self, label: bytes, n: int) -> bytes:
        sz = struct.pack("<I", n)
        self.s.meta_ad(label, more=False)
        self.s.meta_ad(sz, more=True)
        return self.s.prf(n)


# ---------- self-test --------------------------------------------------------

def _selftest():
    # TestSimpleTranscript from oasisprotocol/curve25519-voi
    t = Transcript(b"test protocol")
    t.append(b"some label", b"some data")
    got = t.challenge(b"challenge", 32).hex()
    want = "d5a21972d0d5fe320c0d263fac7fffb8145aa640af6e9bca177c03c7efcf0615"
    assert got == want, f"simple: got {got}, want {want}"
    print("simple  ok:", got)

    # TestComplexTranscript
    t = Transcript(b"test protocol")
    t.append(b"step1", b"some data")
    data = b"\x63" * 1024
    chl = None
    for _ in range(32):
        chl = t.challenge(b"challenge", 32)
        t.append(b"bigdata", data)
        t.append(b"challengedata", chl)
    got = chl.hex()
    want = "a8c933f54fae76e3f9bea93648c1308e7dfa2152dd51674ff3ca438351cf003c"
    assert got == want, f"complex: got {got}, want {want}"
    print("complex ok:", got)


if __name__ == "__main__":
    _selftest()
