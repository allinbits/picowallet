# M9 Phase 1b -- Secure stub build.
#
# Produces picowallet_secure.elf / .uf2 from secure_stub.c. The image
# lives at 0x10000000 (per memmap_secure.ld); after its main() runs the
# SAU configuration + BXNS, control transfers to the Non-Secure image
# at M9_NONSECURE_FLASH_BASE.
#
# Included from firmware/CMakeLists.txt only when PICOWALLET_TRUSTZONE
# is ON. The PICOWALLET_TRUSTZONE=OFF (default) build path is unchanged.

add_executable(picowallet_secure
    secure_stub.c
    veneers.c
    # Phase 2c: keystore + Ed25519/SHA-512 move from NS to Secure. The seed
    # (TEST_SEED today; encrypted-and-PIN-unlocked in M9.5) and the
    # signing routines never appear in NS flash. NS reaches them only via
    # the cmse_nonsecure_entry veneers in veneers.c.
    ../src/os/crypto/keystore.c
    ../src/os/crypto/monocypher-ed25519.c
    ../src/os/crypto/monocypher.c
)

target_include_directories(picowallet_secure PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}     # for layout.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src   # for os/secure_api.h, os/api.h, os/crypto/*
)

# PICOWALLET_SECURE_BUILD=1 is defined ONLY for the Secure target. Use
# inside keystore.c (and friends) to guard the TEST_SEED + derivation
# code so they DON'T also compile into the NS image: NS still references
# os_crypto_*() symbols, but those become thin veneer wrappers under
# PICOWALLET_TRUSTZONE in the NS build.
target_compile_definitions(picowallet_secure PRIVATE PICOWALLET_SECURE_BUILD=1)

# -mcmse turns on TrustZone-M code generation:
#   - enables MSR msp_ns, BXNS, BLXNS, SG instructions
#   - enables __attribute__((cmse_nonsecure_entry)) and friends
#   - lets the linker pull in cmse_nonsecure_call.o from libgcc
target_compile_options(picowallet_secure PRIVATE -mcmse)

# --cmse-implib: emit Secure Gateway veneers for cmse_nonsecure_entry
#   functions into .gnu.sgstubs (memmap_secure.ld places it at the NSC
#   base).
# --out-implib=<file>: write an import library naming each veneer at its
#   absolute address; the NS image links against this so its calls to
#   s_*() resolve to the SG stub in the NSC region rather than to a
#   Secure-side function the NS linker can't see.
set(M9_NSC_IMPLIB ${CMAKE_CURRENT_BINARY_DIR}/picowallet_secure_implib.a
    CACHE INTERNAL "Path to the NSC import library used by the NS link")
target_link_options(picowallet_secure PRIVATE
    -mcmse
    -Wl,--cmse-implib
    -Wl,--out-implib=${M9_NSC_IMPLIB}
)

target_link_libraries(picowallet_secure
    pico_stdlib
    pico_bootrom   # reset_usb_boot fallback when the NS slot is empty
    hardware_flash # Phase 2b: flash_range_erase / flash_range_program
    hardware_sync  # Phase 2b: save_and_disable_interrupts around flash ops
)

pico_set_linker_script(picowallet_secure
    ${CMAKE_CURRENT_SOURCE_DIR}/memmap_secure.ld)

# Stub doesn't use stdio at all. Suppress both SDK channels to keep the
# Secure binary lean.
pico_enable_stdio_usb(picowallet_secure 0)
pico_enable_stdio_uart(picowallet_secure 0)

pico_add_extra_outputs(picowallet_secure)
