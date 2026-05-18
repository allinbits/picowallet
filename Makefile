# PicoWallet — thin wrapper over CMake + the host test harness.
# Run `make help` for available targets.

BUILD_DIR     := firmware/build
M9_BUILD_DIR  := firmware/build_m9
UF2           := $(BUILD_DIR)/picowallet.uf2
ELF           := $(BUILD_DIR)/picowallet.elf
M9_UF2_NS     := $(M9_BUILD_DIR)/picowallet.uf2
M9_UF2_S      := $(M9_BUILD_DIR)/m9/picowallet_secure.uf2
VENV          := .venv
PYTHON        := $(VENV)/bin/python
PIP           := $(VENV)/bin/pip
SUB_MARKER    := third_party/pico-sdk/pico_sdk_init.cmake

# Default target — invoking `make` with no args builds the firmware.
.DEFAULT_GOAL := build

.PHONY: help build clean distclean submodules flash venv test repl size m9-build m9-clean

help: ## show this help
	@awk 'BEGIN {FS = ":.*?## "} \
	     /^[a-zA-Z_-]+:.*?## / {printf "  \033[1m%-12s\033[0m  %s\n", $$1, $$2}' \
	     $(MAKEFILE_LIST)

build: submodules ## build firmware (default target)
	@cmake -S firmware -B $(BUILD_DIR) -Wno-dev > /dev/null
	@cmake --build $(BUILD_DIR) -j
	@echo "==> $(UF2)"

m9-build: submodules ## build the M9 TrustZone dual-image (Secure stub + NS image)
	@cmake -S firmware -B $(M9_BUILD_DIR) -DPICOWALLET_TRUSTZONE=ON -Wno-dev > /dev/null
	@cmake --build $(M9_BUILD_DIR) -j
	@echo "==> $(M9_UF2_S)"
	@echo "==> $(M9_UF2_NS)"
	@echo "    drag both .uf2 files (Secure first) to RPI-RP2 in BOOTSEL mode"

clean: ## wipe firmware/build/
	rm -rf $(BUILD_DIR)

m9-clean: ## wipe firmware/build_m9/
	rm -rf $(M9_BUILD_DIR)

distclean: clean m9-clean ## wipe both build dirs AND .venv/
	rm -rf $(VENV)

# Marker file means we don't re-run submodule update on every build.
submodules: $(SUB_MARKER) ## init/update git submodules (idempotent)
$(SUB_MARKER):
	git submodule update --init --recursive

# Probe known mount points for the Pico in BOOTSEL mass-storage mode.
RPI_RP2_MOUNTS := /Volumes/RPI-RP2 \
                  /media/$(USER)/RPI-RP2 \
                  /run/media/$(USER)/RPI-RP2
flash: build ## build then copy the .uf2 to a BOOTSEL-mounted Pico
	@MOUNT=""; \
	for m in $(RPI_RP2_MOUNTS); do \
	    [ -d "$$m" ] && MOUNT="$$m" && break; \
	done; \
	if [ -z "$$MOUNT" ]; then \
	    echo "RPI-RP2 not mounted. Hold BOOTSEL while plugging the Pico in,"; \
	    echo "then run 'make flash' again. Probed:"; \
	    for m in $(RPI_RP2_MOUNTS); do echo "    $$m"; done; \
	    exit 1; \
	fi; \
	echo "==> $$MOUNT/"; \
	cp $(UF2) "$$MOUNT/"
	@echo "==> Pico will reboot into the new firmware."

# Host-side test harness venv. Created on first use; reused after.
venv: $(PYTHON) ## one-time: create .venv with the host test deps
$(PYTHON):
	python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet pynacl cryptography pyserial
	@echo "==> $(VENV) ready"

test: venv ## end-to-end gno handshake test (device must be in PrivVal mode)
	$(PYTHON) tools/pwctl.py gno-sc-handshake --sign-height $$(date +%s)

# Open an interactive REPL on the device's CDC serial port (TMKMS mode).
# Probes for /dev/cu.usbmodem* (macOS) and /dev/ttyACM* (Linux).
repl: ## open the TMKMS-mode REPL on the device's CDC port
	@PORT=$$(ls /dev/cu.usbmodem* /dev/ttyACM* 2>/dev/null | head -1); \
	if [ -z "$$PORT" ]; then \
	    echo "No CDC port found. Is the device plugged in and in TMKMS mode?"; \
	    exit 1; \
	fi; \
	echo "==> $$PORT  (Ctrl-A k then y to quit)"; \
	screen "$$PORT" 115200

size: $(ELF) ## report firmware section sizes
	@which arm-none-eabi-size > /dev/null 2>&1 \
	    && arm-none-eabi-size $(ELF) \
	    || (echo "arm-none-eabi-size not found; falling back to ls"; ls -la $(ELF) $(UF2))

test-keccak: ## host-side validation of Keccak-f1600 against SHA3-256("") vector
	@cc -Ifirmware/src -Wall \
	     tools/test_keccak.c firmware/src/os/crypto/keccak.c \
	     -o /tmp/picowallet-test-keccak
	@/tmp/picowallet-test-keccak

test-merlin: ## host-side validation of Merlin transcripts vs curve25519-voi vectors
	@cc -Ifirmware/src -Wall -O2 \
	     tools/test_merlin.c \
	     firmware/src/os/crypto/keccak.c \
	     firmware/src/os/crypto/strobe.c \
	     firmware/src/os/crypto/merlin.c \
	     -o /tmp/picowallet-test-merlin
	@/tmp/picowallet-test-merlin
