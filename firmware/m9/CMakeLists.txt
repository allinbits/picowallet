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
)

target_include_directories(picowallet_secure PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}     # for layout.h
)

# -mcmse turns on TrustZone-M code generation:
#   - enables MSR msp_ns, BXNS, BLXNS, SG instructions
#   - enables __attribute__((cmse_nonsecure_entry)) and friends
#   - lets the linker pull in cmse_nonsecure_call.o from libgcc
target_compile_options(picowallet_secure PRIVATE -mcmse)
target_link_options(picowallet_secure PRIVATE -mcmse)

target_link_libraries(picowallet_secure
    pico_stdlib
)

pico_set_linker_script(picowallet_secure
    ${CMAKE_CURRENT_SOURCE_DIR}/memmap_secure.ld)

# Stub doesn't use stdio at all. Suppress both SDK channels to keep the
# Secure binary lean.
pico_enable_stdio_usb(picowallet_secure 0)
pico_enable_stdio_uart(picowallet_secure 0)

pico_add_extra_outputs(picowallet_secure)
