# M9 Phase 1b -- Secure stub build.
#
# Produces picowallet_secure.elf / .uf2 from secure_stub.c. The image
# lives at 0x10000000 (per memmap_secure.ld); after its main() runs the
# SAU configuration + BXNS, control transfers to the Non-Secure image
# at M9_NONSECURE_FLASH_BASE.
#
# Included from firmware/CMakeLists.txt only when PICOWALLET_TRUSTZONE
# is ON. The PICOWALLET_TRUSTZONE=OFF (default) build path is unchanged.

set(WS_LIB ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/Pico_ePaper_Code/c/lib)

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
    # Phase 4: SHA-256 hardware moves to Secure. NS hits the s_hkdf_*
    # veneers (only HKDF was called from NS in the SecretConnection
    # path). The sha256() / hmac_sha256() impls live here too -- they
    # are reused by hkdf_extract / hkdf_expand on this side.
    ../src/os/crypto/sha256.c
    # Phase 2c3: HWM cache + chain config also move to Secure so the
    # HWM strict-advance check fuses with the sign in one veneer call
    # (s_sign_and_advance). The NS-side copies of these are still
    # compiled into picowallet but their write paths only run via the
    # Phase 2b flash veneers, so the two caches stay convergent.
    ../src/os/storage/chains.c
    ../src/os/storage/hwm_flash.c
    # Phase 2d (display): SPI1, e-paper panel, framebuffer, Pico_ePaper_Code
    # library and all UI layout code (splash, console, mode_select,
    # confirm, factory-reset confirm) live in the Secure image. NS calls
    # these via the s_display_* / s_console_* / s_splash_* / s_mode_select_*
    # / s_factory_reset_with_consent veneers in veneers.c. The shared .c
    # files use #if PICOWALLET_SECURE_BUILD to switch between the NS thin
    # shim (compiled into picowallet) and the real implementation
    # (compiled here).
    ../src/os/hal/display.c
    ../src/os/hal/input.c
    ../src/os/ui/splash.c
    ../src/os/ui/console.c
    ../src/os/ui/mode_select.c
    ../src/os/ui/confirm.c
    ../src/os/ui/factory_reset.c
    # Tiny os_console_log -> console_log wrapper (single function).
    ../src/os/api.c
    ${WS_LIB}/Config/DEV_Config.c
    ${WS_LIB}/e-Paper/EPD_3in7.c
    ${WS_LIB}/GUI/GUI_Paint.c
    ${WS_LIB}/Fonts/font24.c
    ${WS_LIB}/Fonts/font20.c
    ${WS_LIB}/Fonts/font16.c
    ${WS_LIB}/Fonts/font12.c
    ${WS_LIB}/Fonts/font8.c
)

target_include_directories(picowallet_secure PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}     # for layout.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src   # for os/secure_api.h, os/api.h, os/crypto/*
    ${WS_LIB}/Config
    ${WS_LIB}/e-Paper
    ${WS_LIB}/GUI
    ${WS_LIB}/Fonts
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
    hardware_spi   # Phase 2d: SPI1 to e-paper panel
    pico_sha256    # Phase 4: SHA-256 hardware moved Secure-side
)

pico_set_linker_script(picowallet_secure
    ${CMAKE_CURRENT_SOURCE_DIR}/memmap_secure.ld)

# Stub doesn't use stdio at all. Suppress both SDK channels to keep the
# Secure binary lean.
pico_enable_stdio_usb(picowallet_secure 0)
pico_enable_stdio_uart(picowallet_secure 0)

pico_add_extra_outputs(picowallet_secure)
