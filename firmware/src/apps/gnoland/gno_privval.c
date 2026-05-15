#include <string.h>

#include "apps/gnoland/gno_privval.h"

// -- TypeURLs (must match gno's amino package "tm.remotesigner") --
static const char TU_PUBKEY_REQ[]    = "/tm.remotesigner.PubKeyRequest";
static const char TU_PUBKEY_RESP[]   = "/tm.remotesigner.PubKeyResponse";
static const char TU_SIGN_REQ[]      = "/tm.remotesigner.SignRequest";
static const char TU_SIGN_RESP[]     = "/tm.remotesigner.SignResponse";
static const char TU_PUBKEY_ED25519[]= "/tm.PubKeyEd25519";

#define TU_PUBKEY_REQ_LEN     30u
#define TU_PUBKEY_RESP_LEN    31u
#define TU_SIGN_REQ_LEN       28u
#define TU_SIGN_RESP_LEN      29u
#define TU_PUBKEY_ED_LEN      17u

// Amino field-key bytes for fields 1 and 2 with Typ3ByteLength (value 2).
#define KEY_F1_BYTES  0x0a   // (1 << 3) | 2
#define KEY_F2_BYTES  0x12   // (2 << 3) | 2

// ----------------------------------------------------------------------------
// uvarint helpers
// ----------------------------------------------------------------------------

static int decode_uvarint(const uint8_t *buf, size_t len,
                          uint64_t *out_val, size_t *out_consumed) {
    uint64_t val = 0;
    int shift = 0;
    size_t i = 0;
    while (i < len) {
        uint8_t b = buf[i++];
        val |= ((uint64_t)(b & 0x7F)) << shift;
        if ((b & 0x80) == 0) {
            *out_val      = val;
            *out_consumed = i;
            return 0;
        }
        shift += 7;
        if (shift >= 64) return -1;  // varint too long
    }
    return -1;  // truncated
}

static size_t encode_uvarint(uint64_t val, uint8_t *out, size_t out_max) {
    size_t n = 0;
    while (val >= 0x80) {
        if (n >= out_max) return 0;
        out[n++] = (uint8_t)(val | 0x80);
        val >>= 7;
    }
    if (n >= out_max) return 0;
    out[n++] = (uint8_t)val;
    return n;
}

// Decode a length-delimited bytes field (key, then varint length, then data).
// Returns 0 on success and sets *out_bytes/*out_len pointing into buf, plus
// *out_consumed for total bytes consumed (key+length+data).
static int decode_bytes_field(const uint8_t *buf, size_t len, uint8_t expected_key,
                              const uint8_t **out_bytes, size_t *out_len,
                              size_t *out_consumed) {
    if (len < 1 || buf[0] != expected_key) return -1;
    size_t pos = 1;
    uint64_t flen;
    size_t fn;
    if (decode_uvarint(buf + pos, len - pos, &flen, &fn) != 0) return -1;
    pos += fn;
    if (flen > (uint64_t)(len - pos)) return -1;
    *out_bytes    = buf + pos;
    *out_len      = (size_t)flen;
    *out_consumed = pos + (size_t)flen;
    return 0;
}

// ----------------------------------------------------------------------------
// Request decoding
// ----------------------------------------------------------------------------

static int matches_url(const uint8_t *bytes, size_t len,
                       const char *url, size_t url_len) {
    return (len == url_len && memcmp(bytes, url, url_len) == 0);
}

int gno_privval_parse_request(const uint8_t *buf, size_t len,
                              gno_privval_req_t *out_type,
                              const uint8_t **out_sign_bytes,
                              size_t *out_sign_len,
                              size_t *out_consumed) {
    *out_type = GNO_PRIVVAL_REQ_UNKNOWN;
    if (out_sign_bytes) *out_sign_bytes = NULL;
    if (out_sign_len)   *out_sign_len   = 0;

    // 1. Outer uvarint length prefix
    uint64_t outer_len;
    size_t hdr_n;
    if (decode_uvarint(buf, len, &outer_len, &hdr_n) != 0) return -1;
    if (outer_len > (uint64_t)(len - hdr_n)) return -1;

    const uint8_t *any = buf + hdr_n;
    size_t any_len = (size_t)outer_len;
    *out_consumed = hdr_n + any_len;

    // 2. Any.TypeURL field 1
    const uint8_t *type_url = NULL;
    size_t type_url_len = 0;
    size_t cn;
    if (decode_bytes_field(any, any_len, KEY_F1_BYTES,
                           &type_url, &type_url_len, &cn) != 0) return -1;
    size_t after_url = cn;

    // 3. Any.Value field 2 -- optional (omitted when inner is empty)
    const uint8_t *value = NULL;
    size_t value_len = 0;
    if (after_url < any_len) {
        if (decode_bytes_field(any + after_url, any_len - after_url, KEY_F2_BYTES,
                               &value, &value_len, &cn) != 0) return -1;
        // Trailing bytes (after Value) would be malformed.
        if (after_url + cn != any_len) return -1;
    }

    // 4. Dispatch by TypeURL match
    if (matches_url(type_url, type_url_len, TU_PUBKEY_REQ, TU_PUBKEY_REQ_LEN)) {
        *out_type = GNO_PRIVVAL_REQ_PUBKEY;
        return 0;
    }
    if (matches_url(type_url, type_url_len, TU_SIGN_REQ, TU_SIGN_REQ_LEN)) {
        // SignRequest has a single field 1 (SignBytes []byte). The Value field
        // bytes ARE the inner amino encoding of SignRequest.
        if (value == NULL || value_len == 0) return -1;
        const uint8_t *sb;
        size_t sblen;
        if (decode_bytes_field(value, value_len, KEY_F1_BYTES,
                               &sb, &sblen, &cn) != 0) return -1;
        if (cn != value_len) return -1;  // trailing bytes in SignRequest
        *out_type        = GNO_PRIVVAL_REQ_SIGN;
        if (out_sign_bytes) *out_sign_bytes = sb;
        if (out_sign_len)   *out_sign_len   = sblen;
        return 0;
    }

    return -1;  // unknown TypeURL
}

// ----------------------------------------------------------------------------
// Response encoding
// ----------------------------------------------------------------------------

// Helpers: write a "<key, varint len, bytes>" field into a buffer. Returns
// bytes written or 0 on overflow.
static size_t emit_bytes_field(uint8_t key, const uint8_t *bytes, size_t blen,
                               uint8_t *out, size_t out_max) {
    if (out_max < 1) return 0;
    out[0] = key;
    size_t lenN = encode_uvarint((uint64_t)blen, out + 1, out_max - 1);
    if (!lenN) return 0;
    if (out_max < 1 + lenN + blen) return 0;
    memcpy(out + 1 + lenN, bytes, blen);
    return 1 + lenN + blen;
}

size_t gno_privval_encode_pubkey_response(const uint8_t pubkey[32],
                                          uint8_t *out, size_t out_max) {
    // ---- innermost: PubKeyEd25519 ([32]byte) wrapped as implicit struct ----
    //   0x0a, 0x20, <32 bytes>                                       = 34 bytes
    uint8_t pk_inner[34];
    pk_inner[0] = KEY_F1_BYTES;
    pk_inner[1] = 32;
    memcpy(pk_inner + 2, pubkey, 32);

    // ---- Any-wrap that into "/tm.PubKeyEd25519" ----
    //   field 1: TypeURL "/tm.PubKeyEd25519"  = 1+1+17 = 19 bytes
    //   field 2: Value (34-byte pk_inner)     = 1+1+34 = 36 bytes
    //   total = 55 bytes
    uint8_t pk_any[55];
    size_t pos = 0;
    size_t n = emit_bytes_field(KEY_F1_BYTES, (const uint8_t*)TU_PUBKEY_ED25519,
                                TU_PUBKEY_ED_LEN, pk_any + pos, sizeof(pk_any) - pos);
    if (!n) return 0; pos += n;
    n = emit_bytes_field(KEY_F2_BYTES, pk_inner, sizeof(pk_inner),
                         pk_any + pos, sizeof(pk_any) - pos);
    if (!n) return 0; pos += n;

    // ---- PubKeyResponse struct: field 1 is the Any-wrapped PubKey ----
    //   0x0a, varint(55), <55 bytes>          = 1+1+55 = 57 bytes
    uint8_t resp_inner[57];
    n = emit_bytes_field(KEY_F1_BYTES, pk_any, pos, resp_inner, sizeof(resp_inner));
    if (!n) return 0;
    size_t resp_inner_len = n;

    // ---- Outermost: Any-wrap PubKeyResponse + sized prefix ----
    //   Any:
    //     field 1: TypeURL "/tm.remotesigner.PubKeyResponse" = 1+1+31 = 33 bytes
    //     field 2: Value (resp_inner)                        = 1+1+57 = 59 bytes
    //   = 92 bytes
    //   uvarint(92) = 1 byte
    //   total = 93 bytes
    if (out_max < 93) return 0;
    pos = 0;
    n = encode_uvarint(92, out + pos, out_max - pos);
    if (!n) return 0; pos += n;
    n = emit_bytes_field(KEY_F1_BYTES, (const uint8_t*)TU_PUBKEY_RESP,
                         TU_PUBKEY_RESP_LEN, out + pos, out_max - pos);
    if (!n) return 0; pos += n;
    n = emit_bytes_field(KEY_F2_BYTES, resp_inner, resp_inner_len,
                         out + pos, out_max - pos);
    if (!n) return 0; pos += n;
    return pos;
}

size_t gno_privval_encode_sign_response_error(const char *err_msg,
                                              uint8_t *out, size_t out_max) {
    size_t err_len = 0;
    while (err_msg[err_len]) err_len++;

    // RemoteSignerError struct inner: field 1 (Err string) = 0x0a + varint(L) + L
    uint8_t err_inner[260];
    if (err_len > 250) return 0;
    size_t n = emit_bytes_field(KEY_F1_BYTES, (const uint8_t*)err_msg, err_len,
                                err_inner, sizeof(err_inner));
    if (!n) return 0;
    size_t err_inner_len = n;

    // SignResponse outer: field 2 (Error, struct pointer) = Any-less because
    // the field type is the concrete RemoteSignerError, not an interface.
    // 0x12 + varint(err_inner_len) + err_inner
    uint8_t resp_inner[280];
    n = emit_bytes_field(KEY_F2_BYTES, err_inner, err_inner_len,
                         resp_inner, sizeof(resp_inner));
    if (!n) return 0;
    size_t resp_inner_len = n;

    // Outer Any{TypeURL=SignResponse, Value=resp_inner}
    // We don't know the total ahead of time; assemble into a scratch buffer
    // then prepend the uvarint length.
    uint8_t any_buf[320];
    size_t pos = 0;
    n = emit_bytes_field(KEY_F1_BYTES, (const uint8_t*)TU_SIGN_RESP,
                         TU_SIGN_RESP_LEN, any_buf + pos, sizeof(any_buf) - pos);
    if (!n) return 0; pos += n;
    n = emit_bytes_field(KEY_F2_BYTES, resp_inner, resp_inner_len,
                         any_buf + pos, sizeof(any_buf) - pos);
    if (!n) return 0; pos += n;

    size_t out_pos = 0;
    n = encode_uvarint((uint64_t)pos, out + out_pos, out_max - out_pos);
    if (!n) return 0; out_pos += n;
    if (out_max - out_pos < pos) return 0;
    memcpy(out + out_pos, any_buf, pos);
    return out_pos + pos;
}

// ----------------------------------------------------------------------------
// CanonicalVote / CanonicalProposal field walker for HWM extraction.
// Both structs put Type at #1 (varint), Height at #2 (sfixed64),
// Round at #3 (sfixed64). Other fields (BlockID, Timestamp, ChainID, POLRound)
// are skipped. Amino drops default-valued fields, so missing Round = 0.
// ----------------------------------------------------------------------------

#define WIRE_VARINT      0
#define WIRE_8BYTE       1
#define WIRE_BYTELENGTH  2
#define WIRE_4BYTE       5

static int skip_field(const uint8_t *buf, size_t len, size_t *pos, int wire) {
    if (wire == WIRE_VARINT) {
        uint64_t v; size_t n;
        if (decode_uvarint(buf + *pos, len - *pos, &v, &n) != 0) return -1;
        *pos += n;
    } else if (wire == WIRE_8BYTE) {
        if (len - *pos < 8) return -1;
        *pos += 8;
    } else if (wire == WIRE_BYTELENGTH) {
        uint64_t flen; size_t n;
        if (decode_uvarint(buf + *pos, len - *pos, &flen, &n) != 0) return -1;
        *pos += n;
        if (flen > (uint64_t)(len - *pos)) return -1;
        *pos += (size_t)flen;
    } else if (wire == WIRE_4BYTE) {
        if (len - *pos < 4) return -1;
        *pos += 4;
    } else {
        return -1;  // unknown wire type
    }
    return 0;
}

// SignedMsgType values (must match gno's tm2/pkg/bft/types/signed_msg_type.go).
#define GNO_TYPE_PREVOTE    0x01
#define GNO_TYPE_PRECOMMIT  0x02
#define GNO_TYPE_PROPOSAL   0x20

int gno_privval_parse_canonical_sign_bytes(const uint8_t *buf, size_t len,
                                           int32_t *out_type,
                                           int64_t *out_height,
                                           int32_t *out_round,
                                           const char **out_chain_id,
                                           size_t *out_chain_id_len) {
    uint64_t outer_len;
    size_t pos;
    if (decode_uvarint(buf, len, &outer_len, &pos) != 0) return -1;
    if (outer_len != (uint64_t)(len - pos)) return -1;

    int  saw_type   = 0;
    int  saw_height = 0;
    *out_type     = 0;
    *out_height   = 0;
    *out_round    = 0;
    *out_chain_id     = NULL;
    *out_chain_id_len = 0;

    // ChainID lives at field 6 in CanonicalVote, field 7 in CanonicalProposal.
    // Capture both during the walk; pick the right one by Type at the end.
    const uint8_t *f6_bytes = NULL; size_t f6_len = 0;
    const uint8_t *f7_bytes = NULL; size_t f7_len = 0;

    while (pos < len) {
        uint64_t tag;
        size_t   n;
        if (decode_uvarint(buf + pos, len - pos, &tag, &n) != 0) return -1;
        pos += n;
        uint32_t field = (uint32_t)(tag >> 3);
        uint32_t wire  = (uint32_t)(tag & 0x7);

        if (field == 1 && wire == WIRE_VARINT) {
            uint64_t v;
            if (decode_uvarint(buf + pos, len - pos, &v, &n) != 0) return -1;
            *out_type = (int32_t)v;
            pos += n;
            saw_type = 1;
        } else if (field == 2 && wire == WIRE_8BYTE) {
            if (len - pos < 8) return -1;
            uint64_t v = 0;
            for (int i = 0; i < 8; i++) v |= ((uint64_t)buf[pos + i]) << (8 * i);
            *out_height = (int64_t)v;
            pos += 8;
            saw_height = 1;
        } else if (field == 3 && wire == WIRE_8BYTE) {
            if (len - pos < 8) return -1;
            uint64_t v = 0;
            for (int i = 0; i < 8; i++) v |= ((uint64_t)buf[pos + i]) << (8 * i);
            *out_round = (int32_t)(int64_t)v;
            pos += 8;
        } else if (field == 6 && wire == WIRE_BYTELENGTH) {
            uint64_t flen;
            if (decode_uvarint(buf + pos, len - pos, &flen, &n) != 0) return -1;
            pos += n;
            if (flen > (uint64_t)(len - pos)) return -1;
            f6_bytes = buf + pos; f6_len = (size_t)flen;
            pos += flen;
        } else if (field == 7 && wire == WIRE_BYTELENGTH) {
            uint64_t flen;
            if (decode_uvarint(buf + pos, len - pos, &flen, &n) != 0) return -1;
            pos += n;
            if (flen > (uint64_t)(len - pos)) return -1;
            f7_bytes = buf + pos; f7_len = (size_t)flen;
            pos += flen;
        } else {
            if (skip_field(buf, len, &pos, (int)wire) != 0) return -1;
        }
    }

    if (!saw_type || !saw_height) return -1;

    // Dispatch ChainID by message type:
    //   CanonicalProposal has POLRound shifted into field 4, so ChainID is at 7.
    //   CanonicalVote has no POLRound, so ChainID is at 6.
    if (*out_type == GNO_TYPE_PROPOSAL) {
        if (!f7_bytes || f7_len == 0) return -1;
        *out_chain_id     = (const char *)f7_bytes;
        *out_chain_id_len = f7_len;
    } else {
        if (!f6_bytes || f6_len == 0) return -1;
        *out_chain_id     = (const char *)f6_bytes;
        *out_chain_id_len = f6_len;
    }
    return 0;
}

size_t gno_privval_encode_sign_response(const uint8_t sig[64],
                                        uint8_t *out, size_t out_max) {
    // ---- SignResponse struct: field 1 (Signature, []byte) ----
    //   0x0a, varint(64), <64 bytes>          = 1+1+64 = 66 bytes
    // (Error field omitted -- nil pointer in success case.)
    uint8_t resp_inner[66];
    size_t n = emit_bytes_field(KEY_F1_BYTES, sig, 64,
                                resp_inner, sizeof(resp_inner));
    if (!n) return 0;
    size_t resp_inner_len = n;

    // ---- Any-wrap + sized prefix ----
    //   Any:
    //     field 1: TypeURL "/tm.remotesigner.SignResponse" = 1+1+29 = 31 bytes
    //     field 2: Value (resp_inner=66)                   = 1+1+66 = 68 bytes
    //   = 99 bytes
    //   uvarint(99) = 1 byte
    //   total = 100 bytes
    if (out_max < 100) return 0;
    size_t pos = 0;
    n = encode_uvarint(99, out + pos, out_max - pos);
    if (!n) return 0; pos += n;
    n = emit_bytes_field(KEY_F1_BYTES, (const uint8_t*)TU_SIGN_RESP,
                         TU_SIGN_RESP_LEN, out + pos, out_max - pos);
    if (!n) return 0; pos += n;
    n = emit_bytes_field(KEY_F2_BYTES, resp_inner, resp_inner_len,
                         out + pos, out_max - pos);
    if (!n) return 0; pos += n;
    return pos;
}
