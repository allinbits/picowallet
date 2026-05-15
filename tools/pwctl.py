#!/usr/bin/env python3
"""
PicoWallet test harness for the device's Tendermint privval listener.

Usage:
  pwctl.py pubkey                        Get & print validator pubkey.
  pwctl.py sign-vote [--height H] ...    Craft a SignVoteRequest, send,
                                         verify the returned signature.
  pwctl.py replay [--height H]           Send the same SignVoteRequest twice;
                                         first should succeed, second should
                                         get back double_sign_refused.
  pwctl.py gno-sc-handshake              Run the gno.land SecretConnection
                                         handshake against the device; verify
                                         the device's signature and emit ours.

Defaults: host 192.168.7.1, port 26658 (Tendermint privval default).
The gno-sc-handshake subcommand uses --sc-port 26659 instead.
Requires `cryptography` (pip install cryptography) for IETF ChaCha20-Poly1305.
"""

import argparse
import socket
import struct
import sys
import time
from typing import Tuple

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

# Optional: needed only by `gno-sc-handshake`. The IETF (12-byte nonce)
# ChaCha20-Poly1305 isn't exposed by pynacl, so we use `cryptography` here.
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:  # pragma: no cover
    ChaCha20Poly1305 = None


# -----------------------------------------------------------------------------
# Minimal protobuf wire-format helpers.
# -----------------------------------------------------------------------------

def write_varint(val: int) -> bytes:
    # Protobuf encodes signed scalars (non-zigzag) by sign-extending the
    # value to 64-bit two's complement. So -1 becomes the 10-byte varint
    # for uint64 max, not a single 0x7F.
    if val < 0:
        val = (val + (1 << 64)) & ((1 << 64) - 1)
    out = bytearray()
    while val >= 0x80:
        out.append((val & 0x7F) | 0x80)
        val >>= 7
    out.append(val & 0x7F)
    return bytes(out)


def read_varint(buf: bytes, pos: int = 0) -> Tuple[int, int]:
    val, shift = 0, 0
    while True:
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, pos
        shift += 7


def write_varint_field(field: int, val: int) -> bytes:
    return write_varint((field << 3) | 0) + write_varint(val)


def write_bytes_field(field: int, data: bytes) -> bytes:
    return write_varint((field << 3) | 2) + write_varint(len(data)) + data


def write_sfixed64_field(field: int, val: int) -> bytes:
    return write_varint((field << 3) | 1) + struct.pack("<q", val)


def parse_tag(buf: bytes, pos: int) -> Tuple[int, int, int]:
    tag, pos = read_varint(buf, pos)
    return tag >> 3, tag & 7, pos


def find_field_bytes(buf: bytes, target_field: int) -> bytes:
    """Scan a length-delimited protobuf and return the value of the first
    occurrence of the given field number (which must be wire type 2)."""
    pos = 0
    while pos < len(buf):
        field, wire, pos = parse_tag(buf, pos)
        if wire == 0:
            _, pos = read_varint(buf, pos)
        elif wire == 1:
            pos += 8
        elif wire == 2:
            ln, pos = read_varint(buf, pos)
            if field == target_field:
                return buf[pos:pos + ln]
            pos += ln
        elif wire == 5:
            pos += 4
        else:
            raise ValueError(f"unsupported wire type {wire}")
    raise KeyError(f"field {target_field} not found")


# -----------------------------------------------------------------------------
# Message encoders / decoders.
# -----------------------------------------------------------------------------

def encode_block_id(block_hash: bytes, parts_total: int, parts_hash: bytes) -> bytes:
    pth = (
        write_varint_field(1, parts_total)
        + write_bytes_field(2, parts_hash)
    )
    return write_bytes_field(1, block_hash) + write_bytes_field(2, pth)


def encode_timestamp(seconds: int, nanos: int) -> bytes:
    return write_varint_field(1, seconds) + write_varint_field(2, nanos)


def encode_vote_request_body(type_, height, round_, block_id, ts_seconds, ts_nanos,
                             chain_id) -> Tuple[bytes, bytes]:
    """Returns (sign_vote_request_body, canonical_vote_bytes)."""
    ts = encode_timestamp(ts_seconds, ts_nanos)

    # Vote (in the wire/request shape: varint height/round)
    vote = (
        write_varint_field(1, type_)
        + write_varint_field(2, height)
        + write_varint_field(3, round_)
        + write_bytes_field(4, block_id)
        + write_bytes_field(5, ts)
    )

    # CanonicalVote (sfixed64 height/round, plus chain_id at field 6)
    canon = (
        write_varint_field(1, type_)
        + write_sfixed64_field(2, height)
        + write_sfixed64_field(3, round_)
        + write_bytes_field(4, block_id)
        + write_bytes_field(5, ts)
        + write_bytes_field(6, chain_id.encode())
    )

    body = (
        write_bytes_field(1, vote)
        + write_bytes_field(2, chain_id.encode())
    )
    return body, canon


def parse_pubkey_response(msg_body: bytes) -> bytes:
    """msg_body is the inner PubKeyResponse. Returns the ed25519 pubkey."""
    pk = find_field_bytes(msg_body, 1)  # pub_key
    ed = find_field_bytes(pk, 1)  # ed25519
    return ed


def _parse_signed_response(msg_body: bytes, inner_field: int, sig_field: int) -> bytes:
    """Generic SignedXxxResponse parser. `inner_field` is the field of the
    Vote/Proposal inside the response. `sig_field` is the signature field
    number inside that inner message (8 for Vote, 7 for Proposal)."""
    try:
        err = find_field_bytes(msg_body, 2)
    except KeyError:
        pass
    else:
        try:
            desc = find_field_bytes(err, 2).decode("ascii", "replace")
        except KeyError:
            desc = "(no desc)"
        raise RuntimeError(f"device returned error: desc={desc!r}")

    inner = find_field_bytes(msg_body, inner_field)
    pos = 0
    last_sig = None
    while pos < len(inner):
        field, wire, pos = parse_tag(inner, pos)
        if wire == 2:
            ln, pos = read_varint(inner, pos)
            if field == sig_field:
                last_sig = inner[pos:pos + ln]
            pos += ln
        elif wire == 0:
            _, pos = read_varint(inner, pos)
        elif wire == 1:
            pos += 8
        elif wire == 5:
            pos += 4
    if last_sig is None:
        raise RuntimeError("response inner message contained no signature")
    return last_sig


def parse_signed_vote_response(msg_body: bytes) -> bytes:
    return _parse_signed_response(msg_body, inner_field=1, sig_field=8)


def parse_signed_proposal_response(msg_body: bytes) -> bytes:
    return _parse_signed_response(msg_body, inner_field=1, sig_field=7)


# -----------------------------------------------------------------------------
# Wire transport: connect, send framed request, read framed response.
# -----------------------------------------------------------------------------

def send_recv(host: str, port: int, outer_field: int, request_body: bytes) -> bytes:
    """Wraps body in Message{outer_field=...}, frames it, sends, reads one
    framed response, returns the inner Message body."""
    payload = write_bytes_field(outer_field, request_body)
    frame = write_varint(len(payload)) + payload

    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(frame)
        # Read uvarint length
        head = b""
        while True:
            b = s.recv(1)
            if not b:
                raise RuntimeError("connection closed before length")
            head += b
            if b[0] < 0x80:
                break
        ln, _ = read_varint(head, 0)
        # Read body of that length
        body = b""
        while len(body) < ln:
            chunk = s.recv(ln - len(body))
            if not chunk:
                raise RuntimeError("connection closed mid-body")
            body += chunk

    # Outer Message has one length-delimited field; unwrap it.
    _, _, pos = parse_tag(body, 0)
    inner_len, pos = read_varint(body, pos)
    return body[pos:pos + inner_len]


# -----------------------------------------------------------------------------
# Commands.
# -----------------------------------------------------------------------------

def cmd_pubkey(args):
    inner = send_recv(args.host, args.port, outer_field=1, request_body=b"")
    pk = parse_pubkey_response(inner)
    print(f"ed25519 pubkey ({len(pk)} bytes): {pk.hex()}")
    return pk


def cmd_sign_vote(args):
    block_hash = bytes.fromhex(args.block_hash) if args.block_hash else b"\x11" * 32
    parts_hash = bytes.fromhex(args.parts_hash) if args.parts_hash else b"\x22" * 32
    block_id   = encode_block_id(block_hash, args.parts_total, parts_hash)

    body, canon = encode_vote_request_body(
        type_       = args.type,
        height      = args.height,
        round_      = args.round,
        block_id    = block_id,
        ts_seconds  = args.timestamp,
        ts_nanos    = 0,
        chain_id    = args.chain_id,
    )

    # 1. Get pubkey first.
    pk = cmd_pubkey(args)

    # 2. Send the sign request.
    inner = send_recv(args.host, args.port, outer_field=3, request_body=body)
    sig = parse_signed_vote_response(inner)
    print(f"signature ({len(sig)} bytes): {sig.hex()}")

    # 3. Reconstruct sign-input (uvarint-length || canonical bytes) and verify.
    sign_input = write_varint(len(canon)) + canon
    try:
        VerifyKey(pk).verify(sign_input, sig)
        print("signature VERIFIED against device pubkey")
    except BadSignatureError:
        print("signature did NOT verify -- canonical bytes mismatch?")
        sys.exit(1)
    return sig


def cmd_sign_proposal(args):
    """Send a SignProposalRequest, verify the returned signature."""
    block_hash = bytes.fromhex(args.block_hash) if args.block_hash else b"\x11" * 32
    parts_hash = bytes.fromhex(args.parts_hash) if args.parts_hash else b"\x22" * 32
    block_id   = encode_block_id(block_hash, args.parts_total, parts_hash)

    ts = encode_timestamp(args.timestamp, 0)

    # Proposal field order: type, height, round, pol_round, block_id, timestamp.
    proposal = (
        write_varint_field(1, args.type)         # 32 = Proposal
        + write_varint_field(2, args.height)
        + write_varint_field(3, args.round)
        + write_varint_field(4, args.pol_round)
        + write_bytes_field (5, block_id)
        + write_bytes_field (6, ts)
    )

    # CanonicalProposal: sfixed64 for height/round/pol_round, chain_id at f=7.
    canon = (
        write_varint_field(1, args.type)
        + write_sfixed64_field(2, args.height)
        + write_sfixed64_field(3, args.round)
        + write_sfixed64_field(4, args.pol_round)
        + write_bytes_field   (5, block_id)
        + write_bytes_field   (6, ts)
        + write_bytes_field   (7, args.chain_id.encode())
    )

    body = (
        write_bytes_field(1, proposal)
        + write_bytes_field(2, args.chain_id.encode())
    )

    pk = cmd_pubkey(args)
    inner = send_recv(args.host, args.port, outer_field=5, request_body=body)
    sig = parse_signed_proposal_response(inner)
    print(f"signature ({len(sig)} bytes): {sig.hex()}")

    sign_input = write_varint(len(canon)) + canon
    try:
        VerifyKey(pk).verify(sign_input, sig)
        print("signature VERIFIED against device pubkey")
    except BadSignatureError:
        print("signature did NOT verify")
        sys.exit(1)


def _recv_framed(sock: socket.socket) -> bytes:
    """Read one privval frame (uvarint length + body) off `sock` and return
    the inner Message body (after unwrapping the outer length-delimited
    field)."""
    head = b""
    while True:
        b = sock.recv(1)
        if not b:
            raise RuntimeError("connection closed before length")
        head += b
        if b[0] < 0x80:
            break
    ln, _ = read_varint(head, 0)
    body = b""
    while len(body) < ln:
        chunk = sock.recv(ln - len(body))
        if not chunk:
            raise RuntimeError("connection closed mid-body")
        body += chunk
    _, _, pos = parse_tag(body, 0)
    inner_len, pos = read_varint(body, pos)
    return body[pos:pos + inner_len]


def cmd_bench(args):
    """Open one long-lived TCP connection and stream `args.count` SignVote
    requests with incrementing heights. Report latency percentiles +
    throughput. Verifies each signature against the device pubkey."""

    # Fetch pubkey once (separate connection).
    print("fetching pubkey...")
    pk = cmd_pubkey(args)

    block_hash = b"\x11" * 32
    parts_hash = b"\x22" * 32
    block_id   = encode_block_id(block_hash, 1, parts_hash)

    print(f"\nrunning {args.count} sign-votes "
          f"(heights {args.start_height}..{args.start_height + args.count - 1})...")

    timings = []
    t_start = time.perf_counter()

    with socket.create_connection((args.host, args.port), timeout=10) as s:
        for i in range(args.count):
            h = args.start_height + i
            body, canon = encode_vote_request_body(
                type_=1, height=h, round_=0,
                block_id=block_id,
                ts_seconds=1715731200 + i, ts_nanos=0,
                chain_id=args.chain_id,
            )
            payload = write_bytes_field(3, body)
            frame = write_varint(len(payload)) + payload

            t0 = time.perf_counter()
            s.sendall(frame)
            inner = _recv_framed(s)
            t1 = time.perf_counter()

            sig = parse_signed_vote_response(inner)
            sign_input = write_varint(len(canon)) + canon
            try:
                VerifyKey(pk).verify(sign_input, sig)
            except BadSignatureError:
                print(f"sig FAILED at height {h}")
                sys.exit(1)

            timings.append(t1 - t0)
            if (i + 1) % 100 == 0:
                last100 = timings[-100:]
                print(f"  {i+1:5d}/{args.count}: "
                      f"last 100 avg {sum(last100)/len(last100)*1000:.1f} ms")

    t_total = time.perf_counter() - t_start

    timings.sort()
    n = len(timings)

    def pct(p):
        idx = max(0, min(n - 1, int(p / 100.0 * n)))
        return timings[idx]

    print()
    print(f"=== bench: {n} sign-votes over one TCP connection ===")
    print(f"wall time:   {t_total:.2f} s")
    print(f"throughput:  {n / t_total:.1f} signs/sec")
    print(f"per-sign latency (ms):")
    print(f"  min  {timings[0]*1000:7.2f}")
    print(f"  p50  {pct(50)*1000:7.2f}")
    print(f"  p90  {pct(90)*1000:7.2f}")
    print(f"  p95  {pct(95)*1000:7.2f}")
    print(f"  p99  {pct(99)*1000:7.2f}")
    print(f"  max  {timings[-1]*1000:7.2f}")
    print(f"  mean {sum(timings)/n*1000:7.2f}")


def cmd_replay(args):
    print("--- first signing ---")
    cmd_sign_vote(args)
    print("\n--- same (h,r,t) again, expecting refusal ---")
    try:
        cmd_sign_vote(args)
    except RuntimeError as e:
        print(f"got expected error: {e}")
        return
    print("ERROR: device signed twice at the same (h,r,t)")
    sys.exit(1)


# ============================================================================
# gno.land amino MarshalAnySized helpers for the remote-signer protocol.
# Wire format: uvarint length || Any{ field1=TypeURL string, field2=Value bytes }
# See [[reference_gno_handshake_wire]] / gno_privval.c for the byte layout.
# ============================================================================

_TU_PK_REQ   = b"/tm.remotesigner.PubKeyRequest"
_TU_PK_RESP  = b"/tm.remotesigner.PubKeyResponse"
_TU_SIGN_REQ = b"/tm.remotesigner.SignRequest"
_TU_SIGN_RSP = b"/tm.remotesigner.SignResponse"
_TU_PK_ED    = b"/tm.PubKeyEd25519"


def _enc_uvarint(v: int) -> bytes:
    out = bytearray()
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def _dec_uvarint(buf: bytes, pos: int = 0) -> Tuple[int, int]:
    val, shift = 0, 0
    while True:
        b = buf[pos]; pos += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, pos
        shift += 7


def _enc_bytes_field(field_num: int, data: bytes) -> bytes:
    return bytes([(field_num << 3) | 2]) + _enc_uvarint(len(data)) + data


def _dec_bytes_field(buf: bytes, pos: int, expected_key: int) -> Tuple[bytes, int]:
    if buf[pos] != expected_key:
        raise ValueError(f"expected key 0x{expected_key:02x}, got 0x{buf[pos]:02x}")
    pos += 1
    n, pos = _dec_uvarint(buf, pos)
    return buf[pos:pos + n], pos + n


def _gno_encode_pubkey_request() -> bytes:
    any_body = _enc_bytes_field(1, _TU_PK_REQ)  # field 2 (Value) omitted: empty
    return _enc_uvarint(len(any_body)) + any_body


def _gno_encode_sign_request(sign_bytes: bytes) -> bytes:
    inner    = _enc_bytes_field(1, sign_bytes)
    any_body = _enc_bytes_field(1, _TU_SIGN_REQ) + _enc_bytes_field(2, inner)
    return _enc_uvarint(len(any_body)) + any_body


def _gno_parse_any(plain: bytes) -> Tuple[bytes, bytes]:
    n, pos = _dec_uvarint(plain, 0)
    if pos + n != len(plain):
        raise ValueError(f"trailing bytes after Any payload: {len(plain) - pos - n}")
    type_url, pos = _dec_bytes_field(plain, pos, 0x0a)
    value = b""
    if pos < len(plain):
        value, pos = _dec_bytes_field(plain, pos, 0x12)
    return type_url, value


def _gno_parse_pubkey_response(plain: bytes) -> bytes:
    type_url, value = _gno_parse_any(plain)
    if type_url != _TU_PK_RESP:
        raise ValueError(f"unexpected response TypeURL {type_url!r}")
    # PubKeyResponse.PubKey is an interface -> Any-wrapped PubKeyEd25519
    pk_any, end = _dec_bytes_field(value, 0, 0x0a)
    if end != len(value):
        raise ValueError("PubKeyResponse has unexpected trailing fields")
    pk_url, pk_val = _gno_parse_any(_enc_uvarint(len(pk_any)) + pk_any)
    if pk_url != _TU_PK_ED:
        raise ValueError(f"unexpected pubkey TypeURL {pk_url!r}")
    # PubKeyEd25519 inside Any.Value is wrapped as implicit struct field 1
    pk, end = _dec_bytes_field(pk_val, 0, 0x0a)
    if end != len(pk_val) or len(pk) != 32:
        raise ValueError(f"bad PubKeyEd25519 payload len={len(pk)}")
    return pk


def _gno_parse_sign_response(plain: bytes):
    """Returns (sig, err_msg). Exactly one is non-None for a well-formed reply."""
    type_url, value = _gno_parse_any(plain)
    if type_url != _TU_SIGN_RSP:
        raise ValueError(f"unexpected response TypeURL {type_url!r}")
    sig = None
    err_msg = None
    pos = 0
    while pos < len(value):
        if value[pos] == 0x0a:  # field 1: Signature
            sig, pos = _dec_bytes_field(value, pos, 0x0a)
        elif value[pos] == 0x12:  # field 2: Error (RemoteSignerError struct)
            err_inner, pos = _dec_bytes_field(value, pos, 0x12)
            err_bytes, end = _dec_bytes_field(err_inner, 0, 0x0a)
            err_msg = err_bytes.decode("utf-8", errors="replace")
            if end != len(err_inner):
                raise ValueError("trailing bytes in RemoteSignerError")
        else:
            raise ValueError(f"unexpected SignResponse field 0x{value[pos]:02x}")
    return sig, err_msg


def _gno_canonical_vote_bytes(vote_type: int, height: int,
                              chain_id: str = "test-chain") -> bytes:
    """amino.MarshalSized(CanonicalVote{Type, Height, ChainID}) for HWM testing.
    Other fields (Round=0 default, BlockID, Timestamp) are omitted; the device
    only parses Type/Height/Round for HWM and ignores the rest."""
    body = bytearray()
    body += bytes([0x08]) + _enc_uvarint(vote_type)                  # field 1 Type
    body += bytes([0x11]) + height.to_bytes(8, "little", signed=True) # field 2 Height
    cid = chain_id.encode()
    body += bytes([0x32]) + _enc_uvarint(len(cid)) + cid             # field 6 ChainID
    return _enc_uvarint(len(body)) + bytes(body)


# ============================================================================
# gno.land SecretConnection handshake (HKDF-only variant; no Merlin).
# Mirrors firmware/src/apps/gnoland/secret_connection_gno.{h,c}.
# ============================================================================

GNO_SC_INFO = b"TENDERMINT_SECRET_CONNECTION_KEY_AND_CHALLENGE_GEN"
GNO_SC_FRAME_SIZE        = 1028
GNO_SC_DATA_MAX_SIZE     = 1024
GNO_SC_DATA_LEN_SIZE     = 4
GNO_SC_AEAD_OVERHEAD     = 16
GNO_SC_SEALED_FRAME_SIZE = GNO_SC_FRAME_SIZE + GNO_SC_AEAD_OVERHEAD  # 1044
GNO_SC_EPH_MSG_SIZE      = 35
GNO_SC_AUTH_MSG_SIZE     = 101

# libsodium / gno small-order point blacklist.
GNO_SC_SMALL_ORDER = [
    bytes(32),
    b"\x01" + bytes(31),
    bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
]


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    import hashlib
    import hmac as hmac_mod
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac_mod.new(salt, ikm, hashlib.sha256).digest()
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac_mod.new(prk, t + info + bytes([counter]),
                         hashlib.sha256).digest()
        out += t
        counter += 1
    return bytes(out[:length])


def _gno_sc_nonce(seq: int) -> bytes:
    # 12-byte IETF nonce: first 4 bytes zero, last 8 bytes LE u64 seq.
    return bytes(4) + seq.to_bytes(8, "little")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return bytes(buf)


def _encode_eph_msg(loc_eph_pub: bytes) -> bytes:
    assert len(loc_eph_pub) == 32
    return bytes([34, 0x0a, 0x20]) + loc_eph_pub  # 35 bytes


def _parse_eph_msg(msg: bytes) -> bytes:
    if len(msg) != GNO_SC_EPH_MSG_SIZE or msg[0] != 34 or msg[1] != 0x0a or msg[2] != 0x20:
        raise ValueError(f"bad ephemeral message framing: {msg.hex()}")
    return msg[3:]


def _build_auth_plain(pub: bytes, sig: bytes) -> bytes:
    assert len(pub) == 32 and len(sig) == 64
    return (bytes([100, 0x0a, 0x20]) + pub +
            bytes([0x12, 0x40]) + sig)  # 101 bytes


def _parse_auth_plain(plain: bytes) -> Tuple[bytes, bytes]:
    if (len(plain) != GNO_SC_AUTH_MSG_SIZE
            or plain[0] != 100 or plain[1] != 0x0a or plain[2] != 0x20
            or plain[35] != 0x12 or plain[36] != 0x40):
        raise ValueError(f"bad authSigMessage framing: {plain.hex()}")
    return plain[3:35], plain[37:101]


def _seal_frame(send_key: bytes, send_seq: int, chunk: bytes) -> bytes:
    if ChaCha20Poly1305 is None:
        raise RuntimeError("cryptography package required: pip install cryptography")
    if len(chunk) > GNO_SC_DATA_MAX_SIZE:
        raise ValueError(f"chunk too big: {len(chunk)}")
    frame = bytearray(GNO_SC_FRAME_SIZE)
    frame[:4] = len(chunk).to_bytes(4, "little")
    frame[4:4 + len(chunk)] = chunk
    return ChaCha20Poly1305(send_key).encrypt(_gno_sc_nonce(send_seq), bytes(frame), None)


def _open_frame(recv_key: bytes, recv_seq: int, sealed: bytes) -> bytes:
    if ChaCha20Poly1305 is None:
        raise RuntimeError("cryptography package required: pip install cryptography")
    if len(sealed) != GNO_SC_SEALED_FRAME_SIZE:
        raise ValueError(f"sealed frame size {len(sealed)} != {GNO_SC_SEALED_FRAME_SIZE}")
    plain_frame = ChaCha20Poly1305(recv_key).decrypt(
        _gno_sc_nonce(recv_seq), sealed, None)
    chunk_len = int.from_bytes(plain_frame[:4], "little")
    if chunk_len > GNO_SC_DATA_MAX_SIZE:
        raise ValueError(f"frame chunk_len {chunk_len} > {GNO_SC_DATA_MAX_SIZE}")
    return plain_frame[4:4 + chunk_len]


def cmd_gno_sc_handshake(args):
    from nacl.bindings import crypto_scalarmult, crypto_scalarmult_base
    from nacl.signing import SigningKey

    # 1. Generate our ephemeral X25519 keypair (always random).
    import os as _os
    loc_eph_priv = _os.urandom(32)
    loc_eph_pub  = crypto_scalarmult_base(loc_eph_priv)

    # 2. Generate our long-term Ed25519 keypair. Use --signing-seed for a
    # deterministic peer identity (so the device's auth_keys allowlist can
    # actually be configured to recognize us across runs).
    if args.signing_seed:
        seed = bytes.fromhex(args.signing_seed)
        if len(seed) != 32:
            raise SystemExit("--signing-seed must be 32 hex bytes (64 chars)")
        loc_sign_sk = SigningKey(seed)
    else:
        loc_sign_sk = SigningKey.generate()
    loc_sign_pk = bytes(loc_sign_sk.verify_key)
    print(f"host pubkey     : {loc_sign_pk.hex()}")

    # 3. Connect and exchange ephemerals. The device's TCP driver defers all
    # writes to its on_recv callback (lwIP-in-accept won't write reliably),
    # so we send first and then read its response.
    sock = socket.create_connection((args.host, args.sc_port), timeout=5.0)
    try:
        sock.sendall(_encode_eph_msg(loc_eph_pub))
        dev_eph_msg = _recv_exact(sock, GNO_SC_EPH_MSG_SIZE)
        rem_eph_pub = _parse_eph_msg(dev_eph_msg)
        if rem_eph_pub in GNO_SC_SMALL_ORDER:
            raise RuntimeError("device sent a small-order point")

        # 4. DH + HKDF key derivation. locIsLeast determines which 32B is which.
        dh_secret = crypto_scalarmult(loc_eph_priv, rem_eph_pub)
        loc_is_least = loc_eph_pub < rem_eph_pub
        derived = _hkdf_sha256(dh_secret, salt=b"", info=GNO_SC_INFO, length=96)
        if loc_is_least:
            recv_key, send_key = derived[0:32],  derived[32:64]
        else:
            send_key, recv_key = derived[0:32],  derived[32:64]
        challenge = derived[64:96]

        # 5. Receive device's sealed auth-sig at recv_seq=0; verify its signature.
        dev_sealed = _recv_exact(sock, GNO_SC_SEALED_FRAME_SIZE)
        dev_auth_plain = _open_frame(recv_key, 0, dev_sealed)
        dev_pub, dev_sig = _parse_auth_plain(dev_auth_plain)
        try:
            VerifyKey(dev_pub).verify(challenge, dev_sig)
        except BadSignatureError:
            raise RuntimeError("device's signature over challenge failed verification")

        # 6. Sign the challenge with our long-term key; seal and send.
        loc_sig = loc_sign_sk.sign(challenge).signature
        loc_auth_plain  = _build_auth_plain(loc_sign_pk, loc_sig)
        loc_sealed_auth = _seal_frame(send_key, 0, loc_auth_plain)
        sock.sendall(loc_sealed_auth)

        print(f"handshake ok")
        print(f"  device pubkey   : {dev_pub.hex()}")
        print(f"  loc_is_least    : {loc_is_least}")
        print(f"  challenge       : {challenge.hex()}")

        # After the handshake, both seqs sit at 1 (one frame used for auth).
        send_seq = 1
        recv_seq = 1

        # ---- PubKeyRequest ----
        pubkey_req = _gno_encode_pubkey_request()
        sock.sendall(_seal_frame(send_key, send_seq, pubkey_req))
        send_seq += 1
        resp_sealed = _recv_exact(sock, GNO_SC_SEALED_FRAME_SIZE)
        resp_plain  = _open_frame(recv_key, recv_seq, resp_sealed); recv_seq += 1
        privval_pub = _gno_parse_pubkey_response(resp_plain)
        print(f"  privval pubkey  : {privval_pub.hex()}")
        if privval_pub != dev_pub:
            raise RuntimeError(
                f"PubKeyResponse pubkey {privval_pub.hex()} != "
                f"handshake pubkey {dev_pub.hex()}")

        # Shorthand for one round-trip through the encrypted privval channel.
        def _privval_roundtrip(req_plain, _state=[send_seq, recv_seq]):
            sock.sendall(_seal_frame(send_key, _state[0], req_plain)); _state[0] += 1
            resp_sealed = _recv_exact(sock, GNO_SC_SEALED_FRAME_SIZE)
            resp_plain  = _open_frame(recv_key, _state[1], resp_sealed); _state[1] += 1
            return resp_plain

        # ---- 1. Sign on chain A, expect success and verify the sig ----
        chain_a = args.chain_id
        canon_a = _gno_canonical_vote_bytes(1, args.sign_height, chain_a)
        resp = _privval_roundtrip(_gno_encode_sign_request(canon_a))
        sig, err = _gno_parse_sign_response(resp)
        if err:
            raise RuntimeError(
                f"first sign on {chain_a!r} returned error {err!r} -- "
                f"retry with --sign-height higher than the device's current HWM")
        try:
            VerifyKey(privval_pub).verify(canon_a, sig)
        except BadSignatureError:
            raise RuntimeError("SignResponse signature did not verify")
        print(f"  sign chain={chain_a!r:18} h={args.sign_height}: ok")

        # ---- 2. Sign on chain B at a *lower* height. This MUST succeed if
        #         HWM is properly per-chain; with a global HWM it would be
        #         rejected because height(B) < height(A). We use
        #         sign_height-1 so re-running this test with a bumped
        #         --sign-height keeps chain B's state fresh too. ----
        chain_b   = args.alt_chain_id
        height_b  = args.sign_height - 1
        canon_b   = _gno_canonical_vote_bytes(1, height_b, chain_b)
        resp = _privval_roundtrip(_gno_encode_sign_request(canon_b))
        sig_b, err_b = _gno_parse_sign_response(resp)
        if err_b:
            raise RuntimeError(
                f"chain={chain_b!r} h={height_b} refused with {err_b!r}. "
                f"Could be (a) isolation broken (would fail with a global HWM "
                f"because chain A is at h={args.sign_height} > {height_b}), "
                f"or (b) prior test run already set chain B's HWM >= {height_b}. "
                f"Try bumping --sign-height to disambiguate.")
        try:
            VerifyKey(privval_pub).verify(canon_b, sig_b)
        except BadSignatureError:
            raise RuntimeError("cross-chain SignResponse signature did not verify")
        print(f"  sign chain={chain_b!r:18} h={height_b}: ok (per-chain HWM, "
              f"lower than chain A's h={args.sign_height})")

        # ---- 3. Replay chain A at the SAME (h,r,t). Must be refused. ----
        resp = _privval_roundtrip(_gno_encode_sign_request(canon_a))
        sig3, err3 = _gno_parse_sign_response(resp)
        if sig3 is not None or err3 != "double_sign_refused":
            raise RuntimeError(
                f"expected double_sign_refused on replay of chain={chain_a!r}, "
                f"got sig={sig3!r} err={err3!r}")
        print(f"  replay chain={chain_a!r:16} h={args.sign_height}: refused ok")
    finally:
        sock.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.7.1")
    ap.add_argument("--port", type=int, default=26658)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("pubkey").set_defaults(func=cmd_pubkey)

    sv = sub.add_parser("sign-vote")
    sv.add_argument("--type",       type=int, default=1)   # 1=Prevote
    sv.add_argument("--height",     type=int, default=100)
    sv.add_argument("--round",      type=int, default=0)
    sv.add_argument("--chain-id",   default="test-chain")
    sv.add_argument("--block-hash", default=None,
                    help="hex; default 32 bytes of 0x11")
    sv.add_argument("--parts-total",type=int, default=1)
    sv.add_argument("--parts-hash", default=None,
                    help="hex; default 32 bytes of 0x22")
    sv.add_argument("--timestamp",  type=int, default=1715731200)
    sv.set_defaults(func=cmd_sign_vote)

    rp = sub.add_parser("replay")
    for a in ("--type", "--height", "--round", "--chain-id",
              "--block-hash", "--parts-total", "--parts-hash", "--timestamp"):
        # mirror sign-vote args
        pass
    rp.add_argument("--type",       type=int, default=1)
    rp.add_argument("--height",     type=int, default=100)
    rp.add_argument("--round",      type=int, default=0)
    rp.add_argument("--chain-id",   default="test-chain")
    rp.add_argument("--block-hash", default=None)
    rp.add_argument("--parts-total",type=int, default=1)
    rp.add_argument("--parts-hash", default=None)
    rp.add_argument("--timestamp",  type=int, default=1715731200)
    rp.set_defaults(func=cmd_replay)

    sp = sub.add_parser("sign-proposal")
    sp.add_argument("--type",       type=int, default=32)   # 32 = Proposal
    sp.add_argument("--height",     type=int, default=200)
    sp.add_argument("--round",      type=int, default=0)
    sp.add_argument("--pol-round",  type=int, default=-1)
    sp.add_argument("--chain-id",   default="test-chain")
    sp.add_argument("--block-hash", default=None)
    sp.add_argument("--parts-total",type=int, default=1)
    sp.add_argument("--parts-hash", default=None)
    sp.add_argument("--timestamp",  type=int, default=1715731200)
    sp.set_defaults(func=cmd_sign_proposal)

    bn = sub.add_parser("bench",
                        help="benchmark N sign-votes over one connection")
    bn.add_argument("--count",        type=int, default=1000)
    bn.add_argument("--start-height", type=int, default=10000)
    bn.add_argument("--chain-id",     default="test-chain")
    bn.set_defaults(func=cmd_bench)

    gh = sub.add_parser("gno-sc-handshake",
                        help="run the gno.land SecretConnection handshake "
                             "against the device and verify both sides")
    gh.add_argument("--sc-port", type=int, default=26659,
                    help="device's gno SecretConnection listener port")
    gh.add_argument("--sign-height", type=int, default=1_000_000,
                    help="height for the test SignRequest; must exceed the "
                         "device's current HWM for the primary --chain-id.")
    gh.add_argument("--chain-id", default="gno-test-chain-A",
                    help="primary chain_id used for sign + replay tests")
    gh.add_argument("--alt-chain-id", default="gno-test-chain-B",
                    help="alternate chain_id used to verify per-chain HWM isolation")
    gh.add_argument("--signing-seed", default=None,
                    help="32-byte hex seed for the host's long-term Ed25519 key. "
                         "Use a fixed seed if the device has a pinned allowlist "
                         "(see os.auth_add). Default: random per run.")
    gh.set_defaults(func=cmd_gno_sc_handshake)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
