#pragma once
#include <stddef.h>
#include <stdint.h>

// Gno.land remote-signer protocol decoder/encoder.
//
// Wire format: amino MarshalAnySizedWriter -- uvarint length prefix followed
// by a google.protobuf.Any-style wrapper:
//   field 1 (TypeURL, bytes): "/tm.remotesigner.<TypeName>"
//   field 2 (Value,   bytes): inner amino-encoded message (omitted if empty)
//
// Only PubKeyRequest and SignRequest are recognized as requests. Responses
// (PubKeyResponse, SignResponse) are emitted with the same Any-sized wrapper.
//
// All TypeURL strings are matched in full (no prefix-only matching), so
// rogue Any payloads with similar names get rejected.

typedef enum {
    GNO_PRIVVAL_REQ_UNKNOWN = 0,
    GNO_PRIVVAL_REQ_PUBKEY  = 1,
    GNO_PRIVVAL_REQ_SIGN    = 2,
} gno_privval_req_t;

// Parse a single amino-sized request from `buf` (one complete message).
//   buf, len: plaintext bytes of the request (uvarint length + Any payload)
//   *out_type: request type
//   For SIGN, *out_sign_bytes/*out_sign_len point into `buf`; valid until
//   `buf` is overwritten. For PUBKEY, those are unset.
//   *out_consumed: total bytes consumed from buf (including uvarint prefix).
// Returns 0 on success; -1 on framing or wire-format error.
int gno_privval_parse_request(const uint8_t *buf, size_t len,
                              gno_privval_req_t *out_type,
                              const uint8_t **out_sign_bytes,
                              size_t *out_sign_len,
                              size_t *out_consumed);

// Encode a PubKeyResponse{PubKey: PubKeyEd25519(pubkey)} into `out`.
// Returns the number of bytes written, or 0 if out_max is too small.
size_t gno_privval_encode_pubkey_response(const uint8_t pubkey[32],
                                          uint8_t *out, size_t out_max);

// Encode a SignResponse{Signature: sig} into `out` (success case; Error nil).
// Returns the number of bytes written, or 0 if out_max is too small.
size_t gno_privval_encode_sign_response(const uint8_t sig[64],
                                        uint8_t *out, size_t out_max);

// Encode a SignResponse{Error: {Err: err_msg}} (failure; Signature absent).
// err_msg must be a NUL-terminated string. Returns bytes written, or 0.
size_t gno_privval_encode_sign_response_error(const char *err_msg,
                                              uint8_t *out, size_t out_max);

// Parse gno's canonical sign bytes (amino.MarshalSized(CanonicalVote/Proposal))
// to extract the HWM-relevant fields. Both structs place Type at field 1
// (varint), Height at field 2 (sfixed64), Round at field 3 (sfixed64).
// ChainID is at field 6 in CanonicalVote and field 7 in CanonicalProposal
// (Proposal has an extra POLRound at field 4 that shifts everything later).
// Amino drops zero-valued fields, so round=0 is normal (missing). Type=0 is
// invalid -> we reject.
//
// out_chain_id is set to point inside buf (no copy); valid until buf changes.
// Returns 0 on success; -1 on framing error or missing Type / Height / ChainID.
int gno_privval_parse_canonical_sign_bytes(const uint8_t *buf, size_t len,
                                           int32_t *out_type,
                                           int64_t *out_height,
                                           int32_t *out_round,
                                           const char **out_chain_id,
                                           size_t *out_chain_id_len);
