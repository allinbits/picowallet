// USB-Ethernet (CDC-ECM) + lwIP + TCP listener for PrivVal mode.
//
// Validator host gets a new Ethernet interface when this device is plugged
// in. Device sits at 192.168.7.1/24 (no DHCP server yet -- host configures
// 192.168.7.2 manually). TCP listener on 26658 currently echoes; Step 3b
// replaces it with Tendermint privval handler.
//
// All of this only runs when os_current_mode == OS_MODE_PRIVVAL. In TMKMS
// mode this file's functions are never called.

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "tusb.h"

#include "lwip/init.h"
#include "lwip/timeouts.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "netif/ethernet.h"
#include "lwip/ip4_addr.h"

#include "os/transport/eth.h"

#if PICOWALLET_TRUSTZONE
#include "os/secure_api.h"

// LWIP_RAND override target. lwipopts.h forwards LWIP_RAND() here so
// lwIP's UDP source-port salt + TCP ISN come from the Secure TRNG
// rather than pico_rand's ROSC sampler -- Phase 4 locks the CLOCKS /
// ROSC peripherals to Secure-only and pico_rand's get_rand_*() would
// fault on its ROSC-running check. Boundary crossings here are rare
// (initial socket setup + retransmission jitter) so the SG round-trip
// cost is irrelevant.
uint32_t picowallet_lwip_rand(void) {
    uint32_t r = 0;
    s_random((uint8_t *)&r, sizeof(r));
    return r;
}
#endif

#define DEVICE_IP_STR     "192.168.7.1"
#define NETMASK_STR       "255.255.255.0"
#define GATEWAY_STR       "0.0.0.0"

// Required by TinyUSB's ECM class driver -- see usb_descriptors.c, where
// this same symbol is also referenced for the iMACAddress string.
extern uint8_t tud_network_mac_address[6];

static struct netif       netif_data;
static struct pbuf       *received_frame;

// ----------------------------------------------------------------------------
// TinyUSB network callbacks (called by ECM class driver in TinyUSB).
// ----------------------------------------------------------------------------

bool tud_network_recv_cb(const uint8_t *src, uint16_t size) {
    if (received_frame) return false;
    if (size == 0)      return true;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, size, PBUF_POOL);
    if (!p) return false;
    memcpy(p->payload, src, size);
    received_frame = p;
    return true;
}

uint16_t tud_network_xmit_cb(uint8_t *dst, void *ref, uint16_t arg) {
    (void)arg;
    struct pbuf *p = (struct pbuf *)ref;
    return pbuf_copy_partial(p, dst, p->tot_len, 0);
}

void tud_network_init_cb(void) {
    if (received_frame) {
        pbuf_free(received_frame);
        received_frame = NULL;
    }
}

// ----------------------------------------------------------------------------
// lwIP netif integration.
// ----------------------------------------------------------------------------

static err_t link_output_fn(struct netif *netif, struct pbuf *p) {
    (void)netif;
    if (!tud_ready())                      return ERR_USE;
    if (!tud_network_can_xmit(p->tot_len)) return ERR_WOULDBLOCK;
    tud_network_xmit(p, 0);
    return ERR_OK;
}

static err_t netif_init_callback(struct netif *netif) {
    netif->mtu        = 1514;
    netif->flags      = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;
    netif->state      = NULL;
    netif->name[0]    = 'E';
    netif->name[1]    = 'X';
    netif->linkoutput = link_output_fn;
    netif->output     = etharp_output;
    return ERR_OK;
}

static void init_lwip(void) {
    lwip_init();

    ip4_addr_t ip, mask, gw;
    ip4addr_aton(DEVICE_IP_STR, &ip);
    ip4addr_aton(NETMASK_STR,   &mask);
    ip4addr_aton(GATEWAY_STR,   &gw);

    netif_data.hwaddr_len = 6;
    memcpy(netif_data.hwaddr, tud_network_mac_address, 6);
    netif_data.hwaddr[5] ^= 0x01;  // device MAC differs from host's by 1 bit

    netif_add(&netif_data, &ip, &mask, &gw, NULL, netif_init_callback, ip4_input);
    netif_set_default(&netif_data);
    netif_set_up(&netif_data);
    netif_set_link_up(&netif_data);  // mandatory for USB-ETH: see memory
}

// ----------------------------------------------------------------------------
// Public API.
// ----------------------------------------------------------------------------
// eth_init is intentionally just the transport: USB-ETH + lwIP + netif up.
// TCP listeners belong to apps (apps/cosmos/privval.c installs the privval
// listener on port 26658). main.c calls them after eth_init().

void eth_init(void) {
    init_lwip();
}

void eth_service(void) {
    if (received_frame) {
        ethernet_input(received_frame, &netif_data);
        received_frame = NULL;
        tud_network_recv_renew();
    }
    sys_check_timeouts();
}
