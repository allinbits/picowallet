// Cosmos / CometBFT privval message parser + handlers.
//
// Wire framing: uvarint length prefix + length-delimited protobuf body
// (Tendermint privval). Bytes arrive via `privval_feed_byte()` from the
// cosmos SecretConnection driver (apps/cosmos/sc_driver_cosmos.c).
// Responses are written through the caller-supplied `privval_sink_t`,
// which the SC driver implements as "buffer this frame, then seal it".
//
// Parser state is caller-owned (privval_state_t in privval.h) so the
// driver can host concurrent privval sessions, one per SC connection.

#include <stdio.h>
#include <string.h>

#include "apps/cosmos/privval.h"
#include "os/api.h"
#include "os/crypto/keystore.h"
#include "os/storage/hwm_flash.h"

#define FRAME_MAX       PRIVVAL_FRAME_MAX
#define PHASE_LEN       0
#define PHASE_BODY      1

static void state_reset_framing(privval_state_t *st) {
    st->phase     = PHASE_LEN;
    st->len_value = 0;
    st->len_shift = 0;
    st->body_len  = 0;
    st->body_pos  = 0;
}

// Write `body` as a uvarint-length-prefixed frame through the sink. The
// sink decides whether to deliver as raw TCP or sealed in an AEAD frame.
static void send_framed(privval_sink_t *sink, const uint8_t *body, size_t len) {
    uint8_t hdr[10];
    size_t  hdr_n = 0;
    uint64_t l = len;
    while (l >= 0x80) {
        hdr[hdr_n++] = (uint8_t)(l | 0x80);
        l >>= 7;
    }
    hdr[hdr_n++] = (uint8_t)l;
    sink->write(sink->ctx, hdr,  hdr_n);
    sink->write(sink->ctx, body, len);
    sink->flush(sink->ctx);
}

// Read a protobuf varint from `buf`. Returns 0 on success and writes the
// value to *out and the number of bytes consumed to *consumed.
static int pb_read_varint(const uint8_t *buf, size_t len,
                          uint64_t *out, size_t *consumed) {
    uint64_t val = 0;
    int shift = 0;
    size_t i = 0;
    while (i < len) {
        uint8_t b = buf[i++];
        val |= ((uint64_t)(b & 0x7F)) << shift;
        if ((b & 0x80) == 0) {
            *out = val;
            *consumed = i;
            return 0;
        }
        shift += 7;
        if (shift >= 64) return -1;  // varint too long
    }
    return -1;  // truncated
}

// Tendermint privval.Message oneof field numbers. The first tag in an
// incoming frame tells us which variant the host sent.
static const char *msg_type_name(uint32_t field) {
    switch (field) {
        case 1: return "PubKeyRequest";
        case 2: return "PubKeyResponse";
        case 3: return "SignVoteRequest";
        case 4: return "SignedVoteResponse";
        case 5: return "SignProposalRequest";
        case 6: return "SignedProposalResponse";
        case 7: return "PingRequest";
        case 8: return "PingResponse";
        default: return "Unknown";
    }
}

// ===========================================================================
// Minimal protobuf decoder
// ===========================================================================

// Read a tag (field<<3 | wire). Returns bytes consumed, or -1.
static int pb_read_tag(const uint8_t *buf, size_t len,
                       uint32_t *field, uint32_t *wire) {
    uint64_t tag;
    size_t   consumed;
    if (pb_read_varint(buf, len, &tag, &consumed) < 0) return -1;
    *field = (uint32_t)(tag >> 3);
    *wire  = (uint32_t)(tag & 7);
    return (int)consumed;
}

// Skip a field's value given its wire type. Returns bytes consumed, or -1.
static int pb_skip_value(const uint8_t *buf, size_t len, uint32_t wire) {
    switch (wire) {
        case 0: {  // varint
            uint64_t v; size_t n;
            if (pb_read_varint(buf, len, &v, &n) < 0) return -1;
            return (int)n;
        }
        case 1:  // 64-bit fixed
            return (len < 8) ? -1 : 8;
        case 2: {  // length-delimited
            uint64_t l; size_t n;
            if (pb_read_varint(buf, len, &l, &n) < 0) return -1;
            if (n + l > len) return -1;
            return (int)(n + l);
        }
        case 5:  // 32-bit fixed
            return (len < 4) ? -1 : 4;
    }
    return -1;
}

// ===========================================================================
// Minimal protobuf builder
// ===========================================================================

static size_t pb_write_varint(uint8_t *buf, uint64_t val) {
    size_t n = 0;
    while (val >= 0x80) { buf[n++] = (uint8_t)(val | 0x80); val >>= 7; }
    buf[n++] = (uint8_t)val;
    return n;
}

// Write a length-delimited field (wire type 2): tag, length-varint, then data.
static size_t pb_write_bytes(uint8_t *buf, uint32_t field,
                             const uint8_t *data, size_t len) {
    size_t n = 0;
    n += pb_write_varint(buf + n, ((uint64_t)field << 3) | 2);
    n += pb_write_varint(buf + n, (uint64_t)len);
    memcpy(buf + n, data, len);
    return n + len;
}

// Write a varint field (wire type 0).
static size_t pb_write_varint_field(uint8_t *buf, uint32_t field, uint64_t val) {
    size_t n = 0;
    n += pb_write_varint(buf + n, ((uint64_t)field << 3) | 0);
    n += pb_write_varint(buf + n, val);
    return n;
}

// ===========================================================================
// Validator key configuration
// ===========================================================================
// Single hardcoded path for now; multi-validator selection lives at M4.
#define VALIDATOR_KEY_PATH "m/0'"

// ===========================================================================
// Response builders
// ===========================================================================

// Outer Message {PingResponse {}}  ->  empty PingResponse at field 8
static void send_ping_response(privval_sink_t *sink) {
    static const uint8_t bytes[] = { 0x42, 0x00 };  // field=8 wire=2, len=0
    send_framed(sink, bytes, sizeof(bytes));
}

// Outer Message {PubKeyResponse {pub_key={ed25519=<32 bytes>}}}
static void send_pubkey_response(privval_sink_t *sink) {
    uint8_t pubkey[32];
    size_t  pubkey_len = 0;
    int rc = os_crypto_get_pubkey(OS_CURVE_ED25519, VALIDATOR_KEY_PATH,
                                  pubkey, sizeof(pubkey), &pubkey_len);
    if (rc != 0) {
        os_console_log("privval: pubkey derive failed");
        send_ping_response(sink);  // best we can do without a proper error type
        return;
    }

    // PublicKey {ed25519=pubkey}      -- ed25519 is field 1, bytes
    uint8_t public_key[40];
    size_t  pk_n = pb_write_bytes(public_key, 1, pubkey, pubkey_len);

    // PubKeyResponse {pub_key=PublicKey}   -- pub_key is field 1, message
    uint8_t pkr[80];
    size_t  pkr_n = pb_write_bytes(pkr, 1, public_key, pk_n);

    // Outer Message {pub_key_response=PubKeyResponse}  -- field 2, message
    uint8_t msg[128];
    size_t  msg_n = pb_write_bytes(msg, 2, pkr, pkr_n);

    send_framed(sink, msg, msg_n);
}

// Build a RemoteSignerError {code=1, description=reason}
static size_t build_remote_signer_error(uint8_t *out, const char *reason) {
    size_t n = 0;
    n += pb_write_varint_field(out + n, 1, 1);  // code = 1
    n += pb_write_bytes(out + n, 2,
                        (const uint8_t *)reason, strlen(reason));
    return n;
}

// Outer Message at outer_field, containing only an error field at error_field.
static void send_error_in(privval_sink_t *sink, uint32_t outer_field,
                          uint32_t error_field, const char *reason) {
    uint8_t err[80];
    size_t  err_n = build_remote_signer_error(err, reason);

    uint8_t resp[128];
    size_t  resp_n = pb_write_bytes(resp, error_field, err, err_n);

    uint8_t msg[160];
    size_t  msg_n = pb_write_bytes(msg, outer_field, resp, resp_n);

    send_framed(sink, msg, msg_n);
}

// ===========================================================================
// Decoded view of an incoming SignVoteRequest / SignProposalRequest
// ===========================================================================
typedef struct {
    int32_t  type;     // SignedMsgType: 1=Prevote, 2=Precommit, 32=Proposal
    int64_t  height;
    int32_t  round;
    int32_t  pol_round;          // proposal only; -1 (or 0) if unused
    char     chain_id[64];

    // BlockID
    uint8_t  block_hash[32];     size_t   block_hash_len;
    uint32_t parts_total;
    uint8_t  parts_hash[32];     size_t   parts_hash_len;
    bool     has_block_id;
    bool     has_parts_header;

    // Timestamp
    int64_t  ts_seconds;
    int32_t  ts_nanos;
    bool     has_timestamp;

    // Raw Vote/Proposal bytes (the inner message at field 1 of the request).
    // We embed these in the response with a signature field appended.
    const uint8_t *vote_raw;
    size_t   vote_raw_len;
} sign_request_t;

// Decode a PartSetHeader { total: uint32, hash: bytes }
static int decode_partset_header(const uint8_t *body, size_t len,
                                 sign_request_t *out) {
    size_t pos = 0;
    while (pos < len) {
        uint32_t f, w;
        int n = pb_read_tag(body + pos, len - pos, &f, &w);
        if (n < 0) return -1;
        pos += n;
        if (f == 1 && w == 0) {
            uint64_t v; size_t vn;
            if (pb_read_varint(body + pos, len - pos, &v, &vn) < 0) return -1;
            out->parts_total = (uint32_t)v;
            pos += vn;
        } else if (f == 2 && w == 2) {
            uint64_t l; size_t ln;
            if (pb_read_varint(body + pos, len - pos, &l, &ln) < 0) return -1;
            pos += ln;
            if (l <= sizeof(out->parts_hash)) {
                memcpy(out->parts_hash, body + pos, l);
                out->parts_hash_len = (size_t)l;
            }
            pos += l;
        } else {
            int sk = pb_skip_value(body + pos, len - pos, w);
            if (sk < 0) return -1;
            pos += sk;
        }
    }
    out->has_parts_header = true;
    return 0;
}

// Decode a BlockID { hash: bytes, part_set_header: PartSetHeader }
static int decode_block_id(const uint8_t *body, size_t len, sign_request_t *out) {
    size_t pos = 0;
    while (pos < len) {
        uint32_t f, w;
        int n = pb_read_tag(body + pos, len - pos, &f, &w);
        if (n < 0) return -1;
        pos += n;
        if (w != 2) {
            int sk = pb_skip_value(body + pos, len - pos, w);
            if (sk < 0) return -1;
            pos += sk;
            continue;
        }
        uint64_t l; size_t ln;
        if (pb_read_varint(body + pos, len - pos, &l, &ln) < 0) return -1;
        pos += ln;
        if (f == 1 && l <= sizeof(out->block_hash)) {
            memcpy(out->block_hash, body + pos, l);
            out->block_hash_len = (size_t)l;
        } else if (f == 2) {
            decode_partset_header(body + pos, (size_t)l, out);
        }
        pos += l;
    }
    out->has_block_id = true;
    return 0;
}

// Decode a Timestamp { seconds: int64, nanos: int32 }
static int decode_timestamp(const uint8_t *body, size_t len, sign_request_t *out) {
    size_t pos = 0;
    while (pos < len) {
        uint32_t f, w;
        int n = pb_read_tag(body + pos, len - pos, &f, &w);
        if (n < 0) return -1;
        pos += n;
        if (w == 0) {
            uint64_t v; size_t vn;
            if (pb_read_varint(body + pos, len - pos, &v, &vn) < 0) return -1;
            if (f == 1) out->ts_seconds = (int64_t)v;
            else if (f == 2) out->ts_nanos = (int32_t)v;
            pos += vn;
        } else {
            int sk = pb_skip_value(body + pos, len - pos, w);
            if (sk < 0) return -1;
            pos += sk;
        }
    }
    out->has_timestamp = true;
    return 0;
}

// Decode the Vote/Proposal message at `body` (length `len`) into `out`.
// Extracts all fields needed for canonical sign bytes: type/height/round
// plus BlockID and Timestamp submessages.
static int decode_inner_vote_or_proposal(const uint8_t *body, size_t len,
                                         sign_request_t *out) {
    size_t pos = 0;
    while (pos < len) {
        uint32_t field, wire;
        int n = pb_read_tag(body + pos, len - pos, &field, &wire);
        if (n < 0) return -1;
        pos += n;

        if (wire == 0) {
            uint64_t val; size_t vn;
            if (pb_read_varint(body + pos, len - pos, &val, &vn) < 0) return -1;
            pos += vn;
            switch (field) {
                case 1: out->type   = (int32_t)val; break;
                case 2: out->height = (int64_t)val; break;
                case 3: out->round  = (int32_t)val; break;
                default: break;
            }
        } else if (wire == 2) {
            uint64_t l; size_t ln;
            if (pb_read_varint(body + pos, len - pos, &l, &ln) < 0) return -1;
            pos += ln;
            if (field == 4) {                            // block_id
                decode_block_id(body + pos, (size_t)l, out);
            } else if (field == 5) {                     // timestamp
                decode_timestamp(body + pos, (size_t)l, out);
            }
            pos += l;
        } else {
            int sk = pb_skip_value(body + pos, len - pos, wire);
            if (sk < 0) return -1;
            pos += sk;
        }
    }
    return 0;
}

// Decode the inner Proposal message. Field numbering differs from Vote:
//   1 type, 2 height, 3 round, 4 pol_round, 5 block_id, 6 timestamp,
//   7 signature, ...
static int decode_inner_proposal(const uint8_t *body, size_t len,
                                 sign_request_t *out) {
    out->pol_round = -1;
    size_t pos = 0;
    while (pos < len) {
        uint32_t field, wire;
        int n = pb_read_tag(body + pos, len - pos, &field, &wire);
        if (n < 0) return -1;
        pos += n;

        if (wire == 0) {
            uint64_t val; size_t vn;
            if (pb_read_varint(body + pos, len - pos, &val, &vn) < 0) return -1;
            pos += vn;
            switch (field) {
                case 1: out->type      = (int32_t)val; break;
                case 2: out->height    = (int64_t)val; break;
                case 3: out->round     = (int32_t)val; break;
                case 4: out->pol_round = (int32_t)val; break;
                default: break;
            }
        } else if (wire == 2) {
            uint64_t l; size_t ln;
            if (pb_read_varint(body + pos, len - pos, &l, &ln) < 0) return -1;
            pos += ln;
            if (field == 5)      decode_block_id (body + pos, (size_t)l, out);
            else if (field == 6) decode_timestamp(body + pos, (size_t)l, out);
            pos += l;
        } else {
            int sk = pb_skip_value(body + pos, len - pos, wire);
            if (sk < 0) return -1;
            pos += sk;
        }
    }
    return 0;
}

// Decode a SignVoteRequest or SignProposalRequest body. Both share the same
// outer shape:
//   field 1 (message): vote or proposal
//   field 2 (string):  chain_id
// The caller supplies the appropriate inner decoder.
static int decode_sign_request_with(const uint8_t *body, size_t len,
                                    sign_request_t *out,
                                    int (*inner_decode)(const uint8_t*, size_t,
                                                        sign_request_t*)) {
    memset(out, 0, sizeof(*out));
    size_t pos = 0;
    while (pos < len) {
        uint32_t field, wire;
        int n = pb_read_tag(body + pos, len - pos, &field, &wire);
        if (n < 0) return -1;
        pos += n;

        if (wire == 2) {
            uint64_t inner_len; size_t ln;
            if (pb_read_varint(body + pos, len - pos, &inner_len, &ln) < 0) return -1;
            pos += ln;
            if (pos + inner_len > len) return -1;
            if (field == 1) {
                out->vote_raw     = body + pos;
                out->vote_raw_len = (size_t)inner_len;
                if (inner_decode(body + pos, inner_len, out) < 0) return -1;
            } else if (field == 2) {
                size_t c = inner_len < sizeof(out->chain_id) - 1 ?
                           inner_len : sizeof(out->chain_id) - 1;
                memcpy(out->chain_id, body + pos, c);
                out->chain_id[c] = '\0';
            }
            pos += inner_len;
        } else {
            int sk = pb_skip_value(body + pos, len - pos, wire);
            if (sk < 0) return -1;
            pos += sk;
        }
    }
    return 0;
}

// ===========================================================================
// CanonicalVote encoding (what actually gets signed)
// ===========================================================================
// Unlike Vote, CanonicalVote uses sfixed64 for height/round (8 bytes LE)
// rather than varint, so the wire bytes are deterministic regardless of
// the numeric value. The signing input is `uvarint(len) || canonical_bytes`.

static size_t write_sfixed64_field(uint8_t *buf, uint32_t field, uint64_t val) {
    size_t n = 0;
    n += pb_write_varint(buf + n, ((uint64_t)field << 3) | 1);
    for (int i = 0; i < 8; i++) buf[n++] = (uint8_t)(val >> (i * 8));
    return n;
}

// Encode CanonicalBlockID. Mirrors cometbft's gogoproto-generated marshal,
// which OMITS scalar fields whose value is the proto3 default (0/empty).
// CanonicalPartSetHeader inside is ALWAYS emitted (it's nullable=false in
// the proto, so even an empty PartSetHeader becomes `12 00`).
static size_t encode_canonical_block_id(uint8_t *buf, const sign_request_t *r) {
    uint8_t inner[80];
    size_t  in = 0;
    if (r->block_hash_len > 0) {
        in += pb_write_bytes(inner + in, 1, r->block_hash, r->block_hash_len);
    }
    // PartSetHeader is non-nullable in CanonicalBlockID -- always emit field 2.
    uint8_t pth[40];
    size_t  pn = 0;
    if (r->parts_total != 0) {
        pn += pb_write_varint_field(pth + pn, 1, r->parts_total);
    }
    if (r->parts_hash_len > 0) {
        pn += pb_write_bytes(pth + pn, 2, r->parts_hash, r->parts_hash_len);
    }
    in += pb_write_bytes(inner + in, 2, pth, pn);
    return pb_write_bytes(buf, 4, inner, in);
}

// Mirror cometbft's BlockID.IsZero() (empty hash + total=0 + empty parts hash).
// CometBFT's CanonicalizeBlockID returns nil for a zero BlockID, which makes
// field 4 of CanonicalVote / field 5 of CanonicalProposal disappear entirely
// from the sign bytes. We must do the same or signatures over nil-votes won't
// verify. Nil-votes are routine in BFT consensus (e.g. prevote-nil when there
// is no proposal in the current round).
static bool block_id_is_zero(const sign_request_t *r) {
    return r->block_hash_len == 0
        && r->parts_total   == 0
        && r->parts_hash_len == 0;
}

// CanonicalVote. CometBFT's gogoproto MarshalToSizedBuffer wraps every
// scalar field in `if m.X != 0`, so we MUST do the same or sign-bytes for
// any vote where one of those is zero (e.g. round=0, which is every first
// round) will differ from cometbft's. Timestamp is always emitted (field
// is non-nullable in proto); chain_id is omitted when empty.
static size_t encode_canonical_vote(uint8_t *buf, const sign_request_t *r) {
    size_t n = 0;
    if (r->type != 0) {
        n += pb_write_varint_field(buf + n, 1, (uint64_t)r->type);
    }
    if (r->height != 0) {
        n += write_sfixed64_field(buf + n, 2, (uint64_t)r->height);
    }
    if (r->round != 0) {
        n += write_sfixed64_field(buf + n, 3, (uint64_t)(int64_t)r->round);
    }
    if (r->has_block_id && !block_id_is_zero(r)) {
        n += encode_canonical_block_id(buf + n, r);
    }
    // Timestamp is nullable=false in CanonicalVote -- always emit.
    // Inside, each scalar field is omitted when its value is 0.
    {
        uint8_t ts[20];
        size_t  tn = 0;
        if (r->ts_seconds != 0) {
            tn += pb_write_varint_field(ts + tn, 1, (uint64_t)r->ts_seconds);
        }
        if (r->ts_nanos != 0) {
            tn += pb_write_varint_field(ts + tn, 2, (uint64_t)(int64_t)r->ts_nanos);
        }
        n += pb_write_bytes(buf + n, 5, ts, tn);
    }
    size_t chain_id_len = strlen(r->chain_id);
    if (chain_id_len > 0) {
        n += pb_write_bytes(buf + n, 6,
                            (const uint8_t *)r->chain_id, chain_id_len);
    }
    return n;
}

// CanonicalProposal field numbering:
//   1 type, 2 height (sfixed64), 3 round (sfixed64), 4 pol_round (sfixed64),
//   5 block_id, 6 timestamp, 7 chain_id.
// CanonicalProposal. Same proto3-zero-omission contract as CanonicalVote.
// Field numbering: 1 type, 2 height, 3 round, 4 pol_round, 5 block_id,
// 6 timestamp, 7 chain_id. Timestamp is non-nullable -> always emit.
//
// Note pol_round is sfixed64; for the common "no POL" case its WIRE value
// is -1 (not 0), and gogoproto's `if m.PolRound != 0` test still passes,
// so we still emit. Only literal 0 is omitted.
static size_t encode_canonical_proposal(uint8_t *buf, const sign_request_t *r) {
    size_t n = 0;
    if (r->type != 0) {
        n += pb_write_varint_field(buf + n, 1, (uint64_t)r->type);
    }
    if (r->height != 0) {
        n += write_sfixed64_field(buf + n, 2, (uint64_t)r->height);
    }
    if (r->round != 0) {
        n += write_sfixed64_field(buf + n, 3, (uint64_t)(int64_t)r->round);
    }
    if (r->pol_round != 0) {
        n += write_sfixed64_field(buf + n, 4, (uint64_t)(int64_t)r->pol_round);
    }
    if (r->has_block_id && !block_id_is_zero(r)) {
        uint8_t inner[80];
        size_t  in = 0;
        if (r->block_hash_len > 0) {
            in += pb_write_bytes(inner + in, 1, r->block_hash, r->block_hash_len);
        }
        uint8_t pth[40];
        size_t  pn = 0;
        if (r->parts_total != 0) {
            pn += pb_write_varint_field(pth + pn, 1, r->parts_total);
        }
        if (r->parts_hash_len > 0) {
            pn += pb_write_bytes(pth + pn, 2, r->parts_hash, r->parts_hash_len);
        }
        in += pb_write_bytes(inner + in, 2, pth, pn);
        n += pb_write_bytes(buf + n, 5, inner, in);
    }
    {
        uint8_t ts[20];
        size_t  tn = 0;
        if (r->ts_seconds != 0) {
            tn += pb_write_varint_field(ts + tn, 1, (uint64_t)r->ts_seconds);
        }
        if (r->ts_nanos != 0) {
            tn += pb_write_varint_field(ts + tn, 2, (uint64_t)(int64_t)r->ts_nanos);
        }
        n += pb_write_bytes(buf + n, 6, ts, tn);
    }
    size_t chain_id_len = strlen(r->chain_id);
    if (chain_id_len > 0) {
        n += pb_write_bytes(buf + n, 7,
                            (const uint8_t *)r->chain_id, chain_id_len);
    }
    return n;
}

// HWM enforcement lives in os/storage/hwm_flash.{h,c} -- shared across all
// signing apps so flipping between cosmos and gnoland modes cannot bypass
// double-sign protection (one device, one validator key, one HWM).

// ===========================================================================
// Per-message-type dispatch
// ===========================================================================

static void handle_sign_vote(privval_state_t *st, privval_sink_t *sink,
                             const uint8_t *inner, size_t inner_len) {
    sign_request_t r;
    if (decode_sign_request_with(inner, inner_len, &r,
                                 decode_inner_vote_or_proposal) < 0) {
        os_console_log("privval: bad sign request");
        send_error_in(sink, 4, 2, "decode_failed");
        return;
    }

    char log[80];
    snprintf(log, sizeof(log), "vote: t=%d h=%lld r=%d",
             (int)r.type, (long long)r.height, (int)r.round);
    os_console_log(log);

    if (strcmp(r.chain_id, st->expected_chain_id) != 0) {
        char m[96];
        snprintf(m, sizeof(m), "vote: chain_id_mismatch got=%.32s want=%.32s",
                 r.chain_id, st->expected_chain_id);
        os_console_log(m);
        send_error_in(sink, 4, 2, "chain_id_mismatch");
        return;
    }

    if (!hwm_advance(r.chain_id, strlen(r.chain_id),
                     r.type, r.height, r.round)) {
        os_console_log("vote: HWM reject (double-sign)");
        send_error_in(sink, 4, 2, "double_sign_refused");
        return;
    }

    // Build canonical bytes
    uint8_t canon[400];
    size_t  canon_n = encode_canonical_vote(canon, &r);

    // Sign-input = uvarint(canon_n) || canon
    uint8_t sign_in[412];
    size_t  prefix_n = pb_write_varint(sign_in, (uint64_t)canon_n);
    memcpy(sign_in + prefix_n, canon, canon_n);
    size_t  sign_in_len = prefix_n + canon_n;

    // Ed25519 sign
    uint8_t sig[64];
    int rc = os_crypto_sign(OS_CURVE_ED25519, VALIDATOR_KEY_PATH,
                            sign_in, sign_in_len, sig);
    if (rc != 0) {
        os_console_log("vote: sign failed");
        send_error_in(sink, 4, 2, "sign_failed");
        return;
    }

    // Build response Vote = original vote_raw + signature (field 8, bytes).
    // (Tendermint accepts duplicate field 8; the last wins per protobuf spec.)
    uint8_t resp_vote[600];
    size_t  rv_n = 0;
    if (r.vote_raw_len <= sizeof(resp_vote) - 70) {
        memcpy(resp_vote, r.vote_raw, r.vote_raw_len);
        rv_n = r.vote_raw_len;
    }
    rv_n += pb_write_bytes(resp_vote + rv_n, 8, sig, 64);

    // SignedVoteResponse { vote = response_vote }  -- field 1
    uint8_t resp[700];
    size_t  resp_n = pb_write_bytes(resp, 1, resp_vote, rv_n);

    // Outer Message { signed_vote_response = ... }  -- field 4
    uint8_t outer[750];
    size_t  outer_n = pb_write_bytes(outer, 4, resp, resp_n);

    send_framed(sink, outer, outer_n);
    os_console_log("vote: SIGNED");
}

static void handle_sign_proposal(privval_state_t *st, privval_sink_t *sink,
                                 const uint8_t *inner, size_t inner_len) {
    sign_request_t r;
    if (decode_sign_request_with(inner, inner_len, &r,
                                 decode_inner_proposal) < 0) {
        os_console_log("privval: bad proposal request");
        send_error_in(sink, 6, 2, "decode_failed");
        return;
    }

    char log[80];
    snprintf(log, sizeof(log), "prop: t=%d h=%lld r=%d pol=%d",
             (int)r.type, (long long)r.height, (int)r.round, (int)r.pol_round);
    os_console_log(log);

    if (strcmp(r.chain_id, st->expected_chain_id) != 0) {
        char m[96];
        snprintf(m, sizeof(m), "prop: chain_id_mismatch got=%.32s want=%.32s",
                 r.chain_id, st->expected_chain_id);
        os_console_log(m);
        send_error_in(sink, 6, 2, "chain_id_mismatch");
        return;
    }

    if (!hwm_advance(r.chain_id, strlen(r.chain_id),
                     r.type, r.height, r.round)) {
        os_console_log("prop: HWM reject (double-sign)");
        send_error_in(sink, 6, 2, "double_sign_refused");
        return;
    }

    uint8_t canon[400];
    size_t  canon_n = encode_canonical_proposal(canon, &r);

    uint8_t sign_in[412];
    size_t  prefix_n = pb_write_varint(sign_in, (uint64_t)canon_n);
    memcpy(sign_in + prefix_n, canon, canon_n);
    size_t  sign_in_len = prefix_n + canon_n;

    uint8_t sig[64];
    int rc = os_crypto_sign(OS_CURVE_ED25519, VALIDATOR_KEY_PATH,
                            sign_in, sign_in_len, sig);
    if (rc != 0) {
        os_console_log("prop: sign failed");
        send_error_in(sink, 6, 2, "sign_failed");
        return;
    }

    // Response Proposal: original raw bytes + signature field (Proposal field
    // 7, NOT 8 as in Vote).
    uint8_t resp_prop[600];
    size_t  rp_n = 0;
    if (r.vote_raw_len <= sizeof(resp_prop) - 70) {
        memcpy(resp_prop, r.vote_raw, r.vote_raw_len);
        rp_n = r.vote_raw_len;
    }
    rp_n += pb_write_bytes(resp_prop + rp_n, 7, sig, 64);

    // SignedProposalResponse { proposal = ... }  -- field 1
    uint8_t resp[700];
    size_t  resp_n = pb_write_bytes(resp, 1, resp_prop, rp_n);

    // Outer Message { signed_proposal_response = ... }  -- field 6
    uint8_t outer[750];
    size_t  outer_n = pb_write_bytes(outer, 6, resp, resp_n);

    send_framed(sink, outer, outer_n);
    os_console_log("prop: SIGNED");
}

static void handle_frame(privval_state_t *st, privval_sink_t *sink) {
    if (st->body_len == 0) {
        os_console_log("privval: empty frame");
        send_ping_response(sink);
        return;
    }

    uint32_t field, wire;
    int tag_n = pb_read_tag(st->body, st->body_len, &field, &wire);
    if (tag_n < 0) {
        os_console_log("privval: bad outer tag");
        send_ping_response(sink);
        return;
    }

    char log[64];
    snprintf(log, sizeof(log), "privval: %s", msg_type_name(field));
    os_console_log(log);

    // For message-typed variants, peel the length prefix and pass the inner
    // body to the type-specific handler. (Ping has empty body, no inner len.)
    const uint8_t *inner     = NULL;
    size_t         inner_len = 0;
    if (wire == 2 && (size_t)tag_n < st->body_len) {
        uint64_t l; size_t ln;
        if (pb_read_varint(st->body + tag_n,
                           st->body_len - tag_n, &l, &ln) == 0
            && tag_n + ln + l <= st->body_len) {
            inner     = st->body + tag_n + ln;
            inner_len = (size_t)l;
        }
    }

    switch (field) {
        case 1:  // PubKeyRequest
            send_pubkey_response(sink);
            break;
        case 3:  // SignVoteRequest
            handle_sign_vote(st, sink, inner, inner_len);
            break;
        case 5:  // SignProposalRequest
            handle_sign_proposal(st, sink, inner, inner_len);
            break;
        case 7:  // PingRequest
            send_ping_response(sink);
            break;
        default:
            os_console_log("privval: unknown msg type");
            send_ping_response(sink);
    }
}

// ---- Public API used by the cosmos SC driver (apps/cosmos/sc_driver_cosmos.c).
// State is caller-owned, so concurrent privval sessions are supported.

void privval_reset_state(privval_state_t *st, const char *expected_chain_id) {
    state_reset_framing(st);
    memset(st->expected_chain_id, 0, sizeof(st->expected_chain_id));
    if (expected_chain_id) {
        strncpy(st->expected_chain_id, expected_chain_id,
                sizeof(st->expected_chain_id) - 1);
    }
}

// Feed a single byte into the frame state machine.
// Returns 0 on success, -1 if a malformed/oversize frame should kill the conn.
int privval_feed_byte(privval_state_t *st, privval_sink_t *sink, uint8_t b) {
    if (st->phase == PHASE_LEN) {
        // uvarint accumulator
        if (st->len_shift >= 64) return -1;   // varint too long
        st->len_value |= ((uint64_t)(b & 0x7F)) << st->len_shift;
        st->len_shift += 7;
        if ((b & 0x80) == 0) {
            if (st->len_value > FRAME_MAX) return -1;
            st->body_len = (size_t)st->len_value;
            st->body_pos = 0;
            // empty frames are legal (e.g., PingRequest may serialize to 0 bytes)
            if (st->body_len == 0) {
                handle_frame(st, sink);
                state_reset_framing(st);
                return 0;
            }
            st->phase = PHASE_BODY;
        }
        return 0;
    }
    // PHASE_BODY
    st->body[st->body_pos++] = b;
    if (st->body_pos == st->body_len) {
        handle_frame(st, sink);
        state_reset_framing(st);
    }
    return 0;
}
