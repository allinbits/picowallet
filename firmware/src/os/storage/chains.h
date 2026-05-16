#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Per-chain validator configuration. The operator provisions one slot per
// chain this device should sign for, in TMKMS-mode REPL. cosmos slots own a
// dial target (host + port -- device dials cometbft's priv_validator_laddr);
// gno slots own a listen port (gnoland dials in to us). Both kinds
// optionally pin a peer's SecretConnection pubkey, and both always bind an
// expected chain_id; sign requests whose canonical bytes claim a different
// chain_id are refused.
//
//   0 cosmos slots in use -> no outbound dialers launched.
//   0 gno    slots in use -> no listeners bound.
//
// Provisioning is read-only at runtime in PrivVal mode; the table is loaded
// from flash on boot and only mutated through the TMKMS REPL.

#define CHAINS_MAX_PER_FAMILY  8u
#define CHAINS_PUBKEY_LEN     32u
#define CHAINS_LABEL_MAX      16u   // includes NUL
#define CHAINS_CHAIN_ID_MAX   48u   // includes NUL; HWM has its own 64-byte cap

typedef enum {
    CHAINS_FAMILY_COSMOS = 0,
    CHAINS_FAMILY_GNO    = 1,
} chains_family_t;

typedef struct {
    bool     in_use;
    char     label[CHAINS_LABEL_MAX];
    char     chain_id[CHAINS_CHAIN_ID_MAX];
    uint8_t  dial_host[4];   // cosmos: IPv4 of priv_validator_laddr. gno: ignored.
    uint16_t port;           // cosmos: dial port. gno: listen port.
    bool     has_pinned_key;
    uint8_t  pinned_key[CHAINS_PUBKEY_LEN];
} chain_slot_t;

// Load both tables from flash. Call once on boot.
void chains_init(void);

// Number of in-use slots in a family (0..CHAINS_MAX_PER_FAMILY).
size_t chains_count(chains_family_t fam);

// Read-only access to slot at index i in family fam (0..CHAINS_MAX_PER_FAMILY-1).
// Returns NULL if i is out of range. The returned pointer is stable until the
// next chains_add/chains_remove/chains_wipe call.
const chain_slot_t *chains_get(chains_family_t fam, size_t i);

// Look up a slot by operator label. NULL if no match.
const chain_slot_t *chains_find_by_label(chains_family_t fam, const char *label);

// Add a slot. Returns 0 on success, negative on error:
//   -1 family table full
//   -2 label already in use in this family
//   -3 chain_id already in use in this family
//   -4 invalid input (empty/oversize label or chain_id, port==0, missing
//      dial_host for cosmos)
//
// `pinned_key` may be NULL to leave the slot permissive; otherwise it must
// be CHAINS_PUBKEY_LEN bytes and non-zero.
int chains_add(chains_family_t fam,
               const char *label,
               const char *chain_id,
               const uint8_t dial_host[4],
               uint16_t port,
               const uint8_t pinned_key[CHAINS_PUBKEY_LEN]);

// Remove a slot by label. Returns true if a slot was removed.
bool chains_remove(chains_family_t fam, const char *label);

// Wipe all slots in both families and persist the empty table.
void chains_wipe(void);
