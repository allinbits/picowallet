cmake_minimum_required(VERSION 3.13)

set(PICO_BOARD pico2 CACHE STRING "Board type")

# M9: TrustZone-M split. When OFF (default), the firmware builds as a
# single Secure-only image at 0x10000000 (the pre-M9 behavior). When
# ON, the build will produce a dual-image UF2 (Secure stub at
# 0x10000000 + Non-Secure image at 0x10080000); the dual-image plumbing
# lands in M9 Phase 1b. See PLAN.md §M9 and firmware/m9/README.md.
option(PICOWALLET_TRUSTZONE
       "Build with the M9 TrustZone-M split (Phase 1+, requires hardware to validate)"
       OFF)

# Dependencies are git submodules under third_party/. Run:
#   git submodule update --init --recursive
# from the repo root after cloning.
set(PICO_SDK_PATH "${CMAKE_CURRENT_LIST_DIR}/../third_party/pico-sdk"
    CACHE PATH "Path to the pico-sdk submodule")

include(pico_sdk_import.cmake)

project(picowallet C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

set(WS_LIB ${CMAKE_CURRENT_LIST_DIR}/../third_party/Pico_ePaper_Code/c/lib)

# Source layout
#
# - Under PICOWALLET_TRUSTZONE the display + UI + Pico_ePaper_Code library
#   compile only into picowallet_secure. NS sees thin shim variants of
#   display.c / splash.c / console.c / mode_select.c / factory_reset.c via
#   the #if PICOWALLET_TRUSTZONE && !PICOWALLET_SECURE_BUILD pattern, plus
#   confirm.c excluded entirely on the NS side.
# - Without TZ the original single-image build keeps everything in this
#   target.
set(PICOWALLET_DISPLAY_SOURCES
    src/os/hal/display.c
    src/os/ui/console.c
    src/os/ui/confirm.c
    src/os/ui/factory_reset.c
    src/os/ui/splash.c
    src/os/ui/mode_select.c
)
set(PICOWALLET_DISPLAY_LIB_SOURCES
    ${WS_LIB}/Config/DEV_Config.c
    ${WS_LIB}/e-Paper/EPD_3in7.c
    ${WS_LIB}/GUI/GUI_Paint.c
    ${WS_LIB}/Fonts/font24.c
    ${WS_LIB}/Fonts/font20.c
    ${WS_LIB}/Fonts/font16.c
    ${WS_LIB}/Fonts/font12.c
    ${WS_LIB}/Fonts/font8.c
)

add_executable(picowallet
    # OS
    src/os/main.c
    src/os/api.c
    src/os/app_registry.c
    src/os/bench.c
    src/os/mode.c
    src/os/hal/input.c
    src/os/hal/usb_console.c
    ${PICOWALLET_DISPLAY_SOURCES}
    src/os/transport/host_protocol.c
    src/os/transport/usb.c
    src/os/transport/usb_descriptors.c
    src/os/transport/eth.c
    src/os/transport/secret_connection.c
    # ECM/RNDIS class driver in TinyUSB needs rndis_reports.c at link time
    ${PICO_SDK_PATH}/lib/tinyusb/lib/networking/rndis_reports.c
    src/os/crypto/monocypher.c
    src/os/crypto/monocypher-ed25519.c
    src/os/crypto/keystore.c
    src/os/crypto/sha256.c
    src/os/crypto/keccak.c
    src/os/crypto/strobe.c
    src/os/crypto/merlin.c
    src/os/storage/hwm_flash.c
    src/os/storage/chains.c

    # Validator apps (one per chain family)
    src/apps/cosmos/app.c
    src/apps/cosmos/privval.c
    src/apps/cosmos/secret_connection_cosmos.c
    src/apps/cosmos/sc_driver_cosmos.c
    src/apps/gnoland/app.c
    src/apps/gnoland/secret_connection_gno.c
    src/apps/gnoland/sc_driver.c
    src/apps/gnoland/gno_privval.c
)

target_include_directories(picowallet PRIVATE
    src
    src/os/transport          # tusb_config.h lives here
    # rndis_protocol.h, needed by TinyUSB's ECM/RNDIS driver
    ${PICO_SDK_PATH}/lib/tinyusb/lib/networking
)

target_link_libraries(picowallet
    pico_stdlib
    hardware_flash
    tinyusb_device
    tinyusb_board
    pico_unique_id
    # lwIP (needed even in TMKMS mode because TinyUSB's rndis_reports.c
    # references lwIP headers; init is gated to PrivVal mode in Step 3).
    pico_lwip_nosys
    pico_lwip_core4
    pico_lwip_netif
    # Hardware SHA-256 peripheral wrapper (RP2350)
    pico_sha256
    # Hardware TRNG-backed PRNG (RP2350)
    pico_rand
)

# Pre-TZ single-image build: keep the e-paper code in the same target.
# Under TZ this lives in picowallet_secure instead (see m9/CMakeLists.txt).
if(NOT PICOWALLET_TRUSTZONE)
    target_sources(picowallet PRIVATE ${PICOWALLET_DISPLAY_LIB_SOURCES})
    target_include_directories(picowallet PRIVATE
        ${WS_LIB}/Config
        ${WS_LIB}/e-Paper
        ${WS_LIB}/GUI
        ${WS_LIB}/Fonts
    )
    target_link_libraries(picowallet hardware_spi)
endif()

# We provide our own USB descriptors; do NOT enable SDK auto-CDC.
pico_enable_stdio_usb(picowallet 0)
pico_enable_stdio_uart(picowallet 0)
pico_add_extra_outputs(picowallet)

if(PICOWALLET_TRUSTZONE)
    # M9 Phase 1b: dual-image build.
    #
    #   1. The existing `picowallet` target now links at the Non-Secure
    #      flash base (0x10080000) using firmware/m9/memmap_nonsecure.ld.
    #   2. firmware/m9/CMakeLists.txt defines a second target,
    #      `picowallet_secure`, that produces a tiny Secure-side image
    #      linked at 0x10000000 (SAU configuration + BXNS to NS).
    #
    # Boot ROM enters the Secure image; the Secure stub then transfers
    # control to the Non-Secure image. Operator flashes both .uf2 files
    # (combining into one .uf2 is a follow-on).
    pico_set_linker_script(picowallet
        ${CMAKE_CURRENT_LIST_DIR}/m9/memmap_nonsecure.ld)
    # NS-side init has to skip every pico-sdk runtime initializer that
    # touches a Secure-only bootrom function. The RP2350 bootrom only
    # exposes 8 ARM-NS APIs (get_sys_info, checked_flash_op,
    # flash_runtime_to_storage_addr, get_partition_table_info,
    # secure_call, otp_access, reboot, get_b_partition); anything else
    # looked up from NS state returns 0 and crashes the NS image with a
    # bx-to-0. BOOTROM_STATE_RESET is the immediate offender. We let the
    # Secure stub do the bootrom-state reset before BXNS, and skip the
    # NS-side initializers entirely.
    target_compile_definitions(picowallet PRIVATE
        # Surface the TZ mode at C level so source files can #if-guard
        # cmse-aware code paths (veneer call sites, secure_api.h include).
        PICOWALLET_TRUSTZONE=1
        # Bootrom-touching: the lookup table NS sees doesn't include these
        # functions, so NS-side lookup returns 0 and crashes the image.
        PICO_RUNTIME_NO_INIT_BOOTROM_RESET=1
        PICO_RUNTIME_SKIP_INIT_BOOTROM_RESET=1
        PICO_RUNTIME_NO_INIT_PER_CORE_BOOTROM_RESET=1
        PICO_RUNTIME_SKIP_INIT_PER_CORE_BOOTROM_RESET=1
        PICO_RUNTIME_SKIP_INIT_BOOTROM_LOCKING_ENABLE=1
        # RESETS + power-down + spin-locks: ACCESSCTRL allows NS to
        # touch these in Phase 1, but the spin loops in early_resets
        # don't terminate from NS (the RESETS_DONE bits track operations
        # the bootrom expected the Secure side to drive). Have the Secure
        # stub call the same SDK functions before BXNS instead.
        PICO_RUNTIME_SKIP_INIT_EARLY_RESETS=1
        PICO_RUNTIME_SKIP_INIT_USB_POWER_DOWN=1
        PICO_RUNTIME_SKIP_INIT_POST_CLOCK_RESETS=1
        PICO_RUNTIME_SKIP_INIT_SPIN_LOCKS_RESET=1
        PICO_RUNTIME_SKIP_INIT_BOOT_LOCKS_RESET=1
        # CLOCKS / XOSC / PLLs: skipped now that Phase 4 locks these
        # peripherals Secure-only. The Secure stub still runs clocks_init
        # in Secure state (PLLs come up before NS exists). NS's own
        # clock_get_hz cache stays zero -- the only NS caller of it was
        # bench.c and that now uses s_clock_get_hz() instead. SPI moved
        # to Secure in Phase 2d so spi_set_baudrate is no longer called
        # from NS; pico_rand is bypassed via the LWIP_RAND override in
        # lwipopts.h so its ROSC-running check (which reads CLOCKS) never
        # fires from NS either.
        PICO_RUNTIME_SKIP_INIT_CLOCKS=1
        # Coprocessors: NSACR resets with NS access to all coprocessors
        # disabled. NS-side per_core_enable_coprocessors writes CPACR and
        # then executes a coprocessor instruction (vmrs / vlstm pattern)
        # which faults under NSACR=0. picowallet doesn't use FP/DSP in NS,
        # so skip the whole step.
        PICO_RUNTIME_NO_INIT_PER_CORE_ENABLE_COPROCESSORS=1
        PICO_RUNTIME_SKIP_INIT_PER_CORE_ENABLE_COPROCESSORS=1
        # Force NS gpio_*() to use memory-mapped SIO instead of the
        # gpioc coprocessor (CP0). The Secure stub opens CP0 for NS via
        # NSACR + CPACR_NS, but empirically gpio_get() reads through CP0
        # return stale/wrong values from NS state on RP2350 -- button
        # presses don't register even though the live SIO_GPIO_IN bit
        # toggles correctly. Falling back to the SIO MMIO path makes
        # NS gpio reads match what the hardware actually shows.
        PICO_USE_GPIO_COPROCESSOR=0
        # pico_rand's default entropy mix includes a call to bootrom's
        # GET_SYS_INFO(SYS_INFO_BOOT_RANDOM). Like SYS_INFO_CHIP_INFO,
        # that sub-code faults from NS state inside the bootrom even
        # though GET_SYS_INFO as a whole is NS-callable. Disable that
        # source -- pico_rand falls back to ROSC drift + (skipped)
        # board ID, which is enough for lwIP's UDP source-port salt
        # in Phase 1. Phase 2's s_random veneer is the real entropy
        # path for SC handshakes.
        PICO_RAND_SEED_ENTROPY_SRC_BOOT_RANDOM=0
        PICO_RAND_SEED_ENTROPY_SRC_BOARD_ID=0
        # Phase 4 partial: ACCESSCTRL_TRNG locks the TRNG hardware to
        # Secure-only, so pico_rand's TRNG sampler would fault. NS goes
        # through the s_random() veneer (Phase 2e) for any real entropy
        # needs; pico_rand's residual users (lwIP UDP source-port salt)
        # fall back to ROSC drift + timer when the TRNG source is off.
        PICO_RAND_ENTROPY_SRC_TRNG=0
    )
    add_subdirectory(m9)
    # Phase 2: NS image links against the import library that the Secure
    # link produces (`--cmse-implib --out-implib=...`). Each s_*() symbol
    # in this archive resolves to the absolute address of the SG stub in
    # the NSC region, so NS calls land in the Secure Gateway and switch
    # state. picowallet must depend on picowallet_secure so the implib
    # is built first.
    add_dependencies(picowallet picowallet_secure)
    target_link_libraries(picowallet ${M9_NSC_IMPLIB})
    target_include_directories(picowallet PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/src   # already-on path via SDK, but make explicit
    )
    message(STATUS "M9: TrustZone-M dual-image build (picowallet + picowallet_secure)")
else()
    message(STATUS "M9: TrustZone-M split disabled (PICOWALLET_TRUSTZONE=OFF)")
endif()
