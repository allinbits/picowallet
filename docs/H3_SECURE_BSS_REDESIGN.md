# H3 — Secure-BSS secret retention

**Finding from the M9.5 codebase review:** the Secure image holds several
sensitive values in static Secure RAM for the lifetime of a boot:

| Symbol | File | Size | Contents |
|---|---|---|---|
| `s_master_seed` | `firmware/src/os/crypto/keystore.c:74` | 64 B | The unsealed BIP-39 master seed — populated after PIN unlock, used by every DERIVED-path signature |
| `s_pin_cache` | `firmware/src/os/storage/seed_flash.c:243` | 16 B | Plaintext PIN — used to re-derive the KEK on per-slot blob unseal |
| `s_cache` | `firmware/m9/m9_otp.c:24` | 32 B | The per-device OTP secret, after first read |
| `s_argon2_work` | `firmware/src/os/storage/seed_flash.c:54` | 64 KiB | Argon2id workspace — wiped after each compute, but holds KDF intermediates during the ~1 s window |
| `s_trng_buf` | `firmware/m9/trng.c:13` | 24 B | Up to 192 bits of TRNG output that's been read but not yet consumed |

A complete dump of Secure RAM would yield: the whole wallet (seed), the
PIN (in clear), the OTP secret (which defeats the chip-binding step of
the KEK), and a handful of future-random bytes (predicts whatever
ephemeral the next handshake uses). The cascade is total.

## Why it's acceptable today

The M9 design rests on a single load-bearing claim: **the SAU prevents
Non-Secure code from reading Secure RAM.** Phase 6's negative test
exercises this directly — NS code attempting to dereference a Secure
address traps with `SecureFault.AUVIOL`, observed on hardware
(`SFSR=0x48`, `SFAR=0x10000000`). Given that the boundary holds, the
in-RAM secrets are not reachable from any execution that's also
exposed to the network, USB, or any other untrusted input.

The threats that *could* read Secure RAM are out of M9's scope:

| # | Threat | Why M9 doesn't address it |
|---|---|---|
| 6 | Physical adversary dumps QSPI flash externally | At-rest the blobs are PIN-sealed; RAM isn't persistent |
| 7 | Physical adversary attaches SWD | ACCESSCTRL keeps DEBUG NS-only; M10 OTP-fuse disables SWD entirely |
| 8 | Voltage / clock / EM glitching the SAU itself | Out of scope; needs hardware countermeasures (M10+) |
| 9 | Side-channel (power / timing) extraction | Monocypher is constant-time; specialized hardening is out of scope |

So the retention isn't a bug *given the threat model*. It's a
**fragility note**: the boundary is the only thing protecting the
secrets, and a single Secure-side bug that leaks a pointer-sized read
to NS would collapse everything at once.

Two reasons the trade-off is fine for now:

1. **The Secure TCB is small** — the only Secure code that touches NS
   inputs is the veneer surface in `firmware/m9/veneers.c` (~700
   lines, each entry doing `cmse_check_address_range` before deref).
   Plus the trusted-UI render path, which doesn't accept NS pointers.
   The crypto and storage primitives are pure Secure-internal.
   Defect density is low and the boundary is easy to re-audit.

2. **The throughput cost of the alternative is too high.** A validator
   signer is expected to sign one block per second sustained against
   cometbft. Re-deriving the master seed per sign would mean an
   Argon2id (~1 s at 64 KiB / t=3) and a button-press PIN entry on
   every signature. That's incompatible with the use case.

## When it stops being acceptable

- We add a veneer that returns a buffer larger than expected (e.g., a
  length confusion). Then a Secure-side bug equals master seed
  exposure in one step.
- We enable an idle relock without clearing the caches (would defeat
  its own purpose).
- We extend the threat model to physical adversaries — at that point
  M9 alone isn't enough and we need M10 (signed firmware + OTP fuse
  to disable SWD) plus glitching countermeasures.
- We accept code from untrusted contributors into the Secure TCB. The
  current design assumes Secure code is fully audited.

## Redesign approach 1 — Minimum-residence (recommended if H3 becomes
load-bearing)

Surgical changes that reduce the in-RAM exposure without breaking the
signing-throughput requirement:

| Cache | Replace with |
|---|---|
| `s_pin_cache` | Drop. Derive a single 32-byte **master KEK** from `Argon2id(PIN, master_salt)` at unlock time and cache *that* instead. Slot blobs would also be sealed under the master KEK (via a quick HKDF with the slot's per-blob salt), so unsealing them needs only HKDF, not another Argon2id. The plaintext PIN is gone from RAM after the unlock returns. **Cost:** changes the slot-blob format; existing slot blobs need re-sealing on upgrade. ~150 LOC. |
| `s_cache` (OTP) | Re-read OTP on every `derive_kek` call. Bootrom OTP read is ~5–10 ms; under PIN-bind that's already inside the ~1 s Argon2id, so the relative overhead is negligible. Removes the OTP secret from RAM entirely (it lives in OTP, which is Secure-only, but at least it's not duplicated in BSS). **Cost:** ~20 LOC, marginal throughput impact. |
| `s_argon2_work` | No change available. The workspace is by definition the in-progress KDF state. Already wiped immediately on return. The 1-second window is unavoidable. |
| `s_master_seed` | No change without breaking throughput. Could be moved out of `.bss` into an explicit `.uninitialized_data` section so it doesn't end up in linker map output — cosmetic only; the bytes are still in RAM. |
| `s_trng_buf` | Not a secret. Holds *future* random output. No exposure issue. |

This approach reduces the secret-bytes-resident-in-Secure-BSS from
**~96 B + 64 KiB transient** to **~96 B + 64 KiB transient** (the
master KEK is the same size as the PIN it replaces, and the OTP
re-read swap is net zero). The actual win is **eliminating the PIN
itself** from RAM — extracting a 32-byte KEK is identical in
consequence to extracting the master seed (both unlock signing), but
an attacker can't *recover the PIN* and use it to seal new slot
overrides or unlock other operator-supplied flows. Defense in depth.

**Estimated effort:** 2–3 days. Touches `seed_flash.c` (new
`m9_master_kek_*` API), `slot_seed.c` (HKDF-based slot KEK
derivation), `m9_otp.c` (drop the cache), `veneers.c` (`s_pin_unlock`
populates the master-KEK cache instead of the PIN cache), `keystore.c`
(no change — still uses `s_master_seed`).

## Redesign approach 2 — Per-sign re-derivation (rejected)

Drop `s_master_seed`. On every sign, prompt PIN via the trusted UI,
run Argon2id, unseal, sign, wipe. Window of plaintext exposure: ~1 s.

**Why rejected:** a validator signer must sustain ~1 signature/second
against cometbft. PIN-via-buttons (~10 s for 4 digits) + Argon2id
(~1 s) per sign is ~10× slower than the protocol can tolerate.
Operator UX is also unworkable.

Could be acceptable for a *cold* signing device (sign one transaction
at a time, manual confirmation per sign), but that's a different
product than what M9 was scoped for.

## Redesign approach 3 — External secure element (M10 territory)

Move the seed into an attached secure element (ATECC608, SE050,
OPTIGA Trust M). The seed lives in tamper-resistant hardware; the
RP2350 sends sign commands and receives signatures.

**Why deferred:** large hardware + firmware change (new I²C/SPI
peripheral, command protocol, provisioning flow). Belongs in the
production-hardening track (M10 / M11), not as a follow-on to M9.5.

## Recommended path

Stay with the current design. Re-evaluate H3 if any of these change:

- M10 secure-boot lands → physical adversary now in scope → revisit.
- Secure TCB grows materially (new veneers, new parsers Secure-side).
- Code review process changes such that Secure-side code is no
  longer fully audited line-by-line.

If H3 becomes load-bearing, ship approach 1. Approach 2 is
incompatible with the validator-signer throughput requirement;
approach 3 is the right move only as part of a broader M10-class
hardware revision.
