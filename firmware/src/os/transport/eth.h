#pragma once

// Bring up the USB-Ethernet path: TinyUSB ECM network callbacks <-> lwIP
// netif at 192.168.7.1/24 <-> TCP listener on port 26658 (privval default).
// Only call this in PrivVal mode, after usb_init().
void eth_init(void);

// Process inbound frames from TinyUSB into lwIP, run lwIP timeouts.
// Call in PrivVal-mode main loop.
void eth_service(void);
