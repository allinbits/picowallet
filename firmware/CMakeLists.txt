cmake_minimum_required(VERSION 3.13)

set(PICO_BOARD pico2 CACHE STRING "Board type")

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

add_executable(picowallet
    # OS
    src/os/main.c
    src/os/api.c
    src/os/app_registry.c
    src/os/bench.c
    src/os/mode.c
    src/os/hal/display.c
    src/os/hal/input.c
    src/os/hal/usb_console.c
    src/os/ui/console.c
    src/os/ui/confirm.c
    src/os/ui/factory_reset.c
    src/os/ui/splash.c
    src/os/ui/mode_select.c
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
    ${WS_LIB}/Config/DEV_Config.c
    ${WS_LIB}/e-Paper/EPD_3in7.c
    ${WS_LIB}/GUI/GUI_Paint.c
    ${WS_LIB}/Fonts/font24.c
    ${WS_LIB}/Fonts/font20.c
    ${WS_LIB}/Fonts/font16.c
    ${WS_LIB}/Fonts/font12.c
    ${WS_LIB}/Fonts/font8.c
)

target_include_directories(picowallet PRIVATE
    src
    src/os/transport          # tusb_config.h lives here
    # rndis_protocol.h, needed by TinyUSB's ECM/RNDIS driver
    ${PICO_SDK_PATH}/lib/tinyusb/lib/networking
    ${WS_LIB}/Config
    ${WS_LIB}/e-Paper
    ${WS_LIB}/GUI
    ${WS_LIB}/Fonts
)

target_link_libraries(picowallet
    pico_stdlib
    hardware_spi
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

# We provide our own USB descriptors; do NOT enable SDK auto-CDC.
pico_enable_stdio_usb(picowallet 0)
pico_enable_stdio_uart(picowallet 0)
pico_add_extra_outputs(picowallet)
