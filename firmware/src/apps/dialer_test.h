// Minimal outbound-TCP smoke test (diagnostic build only).
//
// Enabled with: cmake -DDIAL_TEST_HOST="192.168.7.2" -DDIAL_TEST_PORT=9999 ...
//
// Goal: isolate the dialer wedge from the cosmos SC driver. Does a single,
// heavily-logged tcp_connect after USB is up, registers ALL callbacks
// (canonical pico-examples pattern: tcp_arg/tcp_err/tcp_recv/tcp_sent/tcp_poll
// before tcp_connect), and renders the on-device console between steps so
// the last visible line tells you exactly where (if anywhere) it hung.
//
// Runs additively: gno_sc_driver (listener, port 26659) is left in place so
// ICMP echo and inbound TCP still work as a control.
#pragma once

void dialer_test_init(void);
void dialer_test_service(void);
