// See dialer_test.h. This whole file compiles to nothing unless DIAL_TEST_HOST
// is defined at the cmake layer.
#include "apps/dialer_test.h"

#ifdef DIAL_TEST_HOST

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tusb.h"

#include "lwip/tcp.h"
#include "lwip/etharp.h"
#include "lwip/ip4_addr.h"
#include "lwip/err.h"

#include "os/api.h"
#include "os/ui/console.h"

#ifndef DIAL_TEST_PORT
#define DIAL_TEST_PORT 9999
#endif

// ECM convention used by our descriptors: tud_network_mac_address is the
// HOST's MAC; the device uses that same value with the low bit of byte 5
// flipped (see eth.c). Useful for an optional static-ARP warmup.
extern uint8_t tud_network_mac_address[6];

static bool             g_done       = false;
static uint32_t         g_ready_ticks = 0;
static struct tcp_pcb  *g_pcb        = NULL;

// Log a line and force a render so we can SEE it on the e-paper before the
// next call -- if the next call wedges, the previous render is what stays
// on screen. The render is ~3 s blocking; that's the cost of visibility.
static void step(const char *msg) {
    os_console_log(msg);
    console_render();
}

static void log_fmt(const char *fmt, ...) {
    char b[64];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    step(b);
}

// --- TCP raw-API callbacks ---------------------------------------------------

static void on_err(void *arg, err_t err) {
    (void)arg;
    log_fmt("dial-test: ERR cb rc=%d", (int)err);
    g_pcb = NULL;   // pcb is already freed by lwIP when tcp_err fires
}

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    (void)arg; (void)err;
    if (!p) {
        step("dial-test: peer closed");
        tcp_close(pcb);
        g_pcb = NULL;
        return ERR_OK;
    }
    log_fmt("dial-test: rx %u bytes", (unsigned)p->tot_len);
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t on_connect(void *arg, struct tcp_pcb *pcb, err_t err) {
    (void)arg; (void)pcb;
    log_fmt("dial-test: CONNECT cb rc=%d", (int)err);
    return ERR_OK;
}

static err_t on_sent(void *arg, struct tcp_pcb *pcb, u16_t len) {
    (void)arg; (void)pcb; (void)len;
    return ERR_OK;
}

static err_t on_poll(void *arg, struct tcp_pcb *pcb) {
    (void)arg; (void)pcb;
    return ERR_OK;
}

// --- Public API --------------------------------------------------------------

void dialer_test_init(void) {
    step("dial-test: armed " DIAL_TEST_HOST);
}

void dialer_test_service(void) {
    if (g_done) return;

    // Only proceed after USB is enumerated. Outbound traffic before
    // enumeration goes nowhere (the host hasn't bound the netif yet) and may
    // be what's wedging the cosmos driver when it dials from a sys_timeout
    // that fires before the host is ready.
    if (!tud_ready()) return;

    // Stabilize: let the host complete enumeration + DHCP-less manual config
    // + initial ARP exchange. Main loop ticks at >>1 kHz, so ~1000 ticks is
    // a small but non-zero settling window.
    if (++g_ready_ticks < 1000) return;

    g_done = true;

#ifdef DIAL_TEST_STATIC_ARP
    // Bypass any ARP resolution wedge by populating the entry directly.
    // tud_network_mac_address is the HOST's MAC per ECM convention.
    {
        ip4_addr_t target;
        if (!ip4addr_aton(DIAL_TEST_HOST, &target)) {
            step("dial-test: bad DIAL_TEST_HOST");
            return;
        }
        struct eth_addr host_eth;
        memcpy(host_eth.addr, tud_network_mac_address, 6);
        err_t arp_e = etharp_add_static_entry(&target, &host_eth);
        log_fmt("dial-test: arp_add rc=%d", (int)arp_e);
    }
#endif

    step("dial-test: tcp_new");
    g_pcb = tcp_new();
    if (!g_pcb) {
        step("dial-test: tcp_new returned NULL");
        return;
    }
    log_fmt("dial-test: pcb=%p", (void *)g_pcb);

    // Canonical pico-examples order: arg first, then every callback, THEN
    // tcp_connect. tcp_arg() ensures callback_arg is NULL rather than
    // whatever memp_malloc left in the slot.
    step("dial-test: set callbacks");
    tcp_arg(g_pcb, NULL);
    tcp_err(g_pcb, on_err);
    tcp_recv(g_pcb, on_recv);
    tcp_sent(g_pcb, on_sent);
    tcp_poll(g_pcb, on_poll, 4);
    step("dial-test: callbacks set");

    ip4_addr_t remote;
    if (!ip4addr_aton(DIAL_TEST_HOST, &remote)) {
        step("dial-test: bad DIAL_TEST_HOST");
        return;
    }

    step("dial-test: tcp_connect");
    err_t e = tcp_connect(g_pcb, &remote, DIAL_TEST_PORT, on_connect);
    log_fmt("dial-test: tcp_connect rc=%d", (int)e);
    // Success path: now wait for on_connect or on_err.
    // Failure path: log already emitted.
}

#else   // DIAL_TEST_HOST not defined: compile to no-ops.

void dialer_test_init(void)    {}
void dialer_test_service(void) {}

#endif
