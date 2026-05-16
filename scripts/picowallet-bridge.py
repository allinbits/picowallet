#!/usr/bin/env python3
"""
TCP forwarder between cometbft's remote-signer listener and the picowallet's
cosmos SC listener.

Topology:
    cometbft node3 (server, listens on  127.0.0.1:26690)
                          ^
                          | bridge dials this
                          |
                     [this script]
                          |
                          | bridge dials this
                          v
    picowallet     (server, listens on  192.168.7.1:26660)

The bridge is a TCP CLIENT to both endpoints and just pipes bytes between
them. cometbft's SC handshake bytes flow from its socket to the
picowallet's socket; replies flow the other way. Both endpoints think
they're talking to a normal peer that called them.

Why this exists: stock cometbft is the TCP listener for remote signing
(the signer must dial in). Our picowallet is also a TCP listener. So
neither will dial the other -- the bridge fills the gap.

The bridge keeps retrying the cometbft side until it comes up, so you
can start the bridge alongside the testnet without worrying about order.
On disconnect (cometbft restart, picowallet reset, etc.) it reconnects.
"""

from __future__ import annotations
import argparse, socket, sys, threading, time


def pipe(src: socket.socket, dst: socket.socket, tag: str, stop: threading.Event):
    try:
        while not stop.is_set():
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        stop.set()
        for s in (src, dst):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass


def session(cometbft_addr, picowallet_addr) -> bool:
    """Run one bridge session: dial both, pipe until either side closes.
    Returns True if a session actually got established (so the caller knows
    whether to back off before retrying)."""
    cb = pw = None
    try:
        cb = socket.create_connection(cometbft_addr, timeout=2.0)
        pw = socket.create_connection(picowallet_addr, timeout=2.0)
    except (OSError, socket.timeout):
        for s in (cb, pw):
            if s is not None:
                try: s.close()
                except OSError: pass
        return False

    cb.settimeout(None); pw.settimeout(None)
    print(f"bridge: {cometbft_addr} <-> {picowallet_addr} established", flush=True)

    stop = threading.Event()
    t1 = threading.Thread(target=pipe, args=(cb, pw, "cb->pw", stop), daemon=True)
    t2 = threading.Thread(target=pipe, args=(pw, cb, "pw->cb", stop), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    for s in (cb, pw):
        try: s.close()
        except OSError: pass
    print(f"bridge: session closed; will reconnect", flush=True)
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cometbft-host", default="127.0.0.1")
    ap.add_argument("--cometbft-port", type=int, default=26690)
    ap.add_argument("--picowallet-host", default="192.168.7.1")
    ap.add_argument("--picowallet-port", type=int, default=26660)
    args = ap.parse_args()

    cb_addr = (args.cometbft_host, args.cometbft_port)
    pw_addr = (args.picowallet_host, args.picowallet_port)
    print(f"bridge: cometbft={cb_addr}  picowallet={pw_addr}", flush=True)

    backoff = 0.5
    while True:
        if session(cb_addr, pw_addr):
            backoff = 0.5     # successful session resets backoff
            time.sleep(0.1)
        else:
            time.sleep(backoff)
            backoff = min(backoff * 1.5, 3.0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
