#!/usr/bin/env python3
"""natcheck — classify this machine's NAT in about five seconds.

Why this exists
---------------
When every peer in the admin dashboard suddenly shows RELAYED after moving to a
different router, the usual cause is that the new router does SYMMETRIC NAT: it
allocates a NEW external port for every destination you talk to. The endpoint
STUN reports is then valid only toward the STUN server, so a peer trying to
hole-punch at that endpoint always hits the wrong port and the pair falls back
to relaying through a mutual peer.

This is invisible from the outside — the node still forms perfectly good direct
sessions with any peer that has a stable, listening endpoint (a VPS, or a node
whose router forwards a port), which is exactly why the failure looks so
selective and confusing.

The test is simple: send STUN binding requests to several different servers from
ONE socket and compare the external ports they report back.

  * same port from every server        -> port-stable NAT. Hole punching works.
  * different port from each server    -> symmetric NAT. NATed peers will relay.

Usage
-----
    python3 natcheck.py                 # test on an ephemeral port
    python3 natcheck.py --port 6969     # test on the overlay's actual UDP port
                                        # (stop the client first — the port must
                                        #  be free)

No dependencies; stdlib only. Works on macOS, Linux and Windows.
"""

import argparse
import os
import secrets
import socket
import struct
import sys

MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_RESPONSE = 0x0101
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020

# Deliberately spread across different operators. Two hostnames belonging to the
# same anycast pool can answer from the same address, which would make a
# symmetric NAT look port-stable — the whole test depends on the destinations
# genuinely being different.
DEFAULT_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("global.stun.twilio.com", 3478),
    ("stun.nextcloud.com", 3478),
]


def stun_request(sock, server, timeout=2.0):
    """Send one STUN binding request; return (reflexive_ip, reflexive_port)."""
    txid = secrets.token_bytes(12)
    packet = struct.pack("!HHI", BINDING_REQUEST, 0, MAGIC_COOKIE) + txid

    try:
        addr = (socket.gethostbyname(server[0]), server[1])
    except socket.gaierror as exc:
        raise RuntimeError(f"DNS lookup failed: {exc}") from exc

    sock.settimeout(timeout)
    sock.sendto(packet, addr)

    # Read until we see a response carrying OUR transaction id. Anything else on
    # this socket (including a reply to an earlier, timed-out probe) is skipped.
    while True:
        data, _ = sock.recvfrom(2048)
        if len(data) < 20:
            continue
        msg_type, msg_len, cookie = struct.unpack("!HHI", data[:8])
        if cookie != MAGIC_COOKIE or data[8:20] != txid:
            continue
        if msg_type != BINDING_RESPONSE:
            raise RuntimeError(f"unexpected STUN message type 0x{msg_type:04x}")
        return parse_attributes(data[20 : 20 + msg_len], txid), addr


def parse_attributes(body, txid):
    """Pull the mapped address out of a binding response body."""
    i = 0
    while i + 4 <= len(body):
        attr_type, attr_len = struct.unpack("!HH", body[i : i + 4])
        value = body[i + 4 : i + 4 + attr_len]
        i += 4 + attr_len
        i += (4 - (attr_len % 4)) % 4  # attributes are 4-byte aligned

        if attr_type == ATTR_XOR_MAPPED_ADDRESS and len(value) >= 8:
            family = value[1]
            port = struct.unpack("!H", value[2:4])[0] ^ (MAGIC_COOKIE >> 16)
            if family == 0x01:  # IPv4
                raw = int.from_bytes(value[4:8], "big") ^ MAGIC_COOKIE
                ip = socket.inet_ntoa(raw.to_bytes(4, "big"))
                return ip, port
        elif attr_type == ATTR_MAPPED_ADDRESS and len(value) >= 8:
            if value[1] == 0x01:
                port = struct.unpack("!H", value[2:4])[0]
                return socket.inet_ntoa(value[4:8]), port
    raise RuntimeError("no mapped address in STUN response")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--port",
        type=int,
        default=0,
        help="local UDP port to bind (default: ephemeral). Use the overlay's "
        "udp_listen_port to test the exact mapping peers will hit — the "
        "client must be stopped so the port is free.",
    )
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", args.port))
    except OSError as exc:
        print(f"cannot bind UDP port {args.port}: {exc}", file=sys.stderr)
        if args.port:
            print("Is the overlay client still running? Stop it and retry.", file=sys.stderr)
        return 2

    local_port = sock.getsockname()[1]
    print(f"probing from local UDP port {local_port}\n")

    results = []
    for server in DEFAULT_SERVERS:
        label = f"{server[0]}:{server[1]}"
        try:
            (ip, port), addr = stun_request(sock, server)
        except (socket.timeout, OSError, RuntimeError) as exc:
            print(f"  {label:<34} no answer ({exc})")
            continue
        print(f"  {label:<34} via {addr[0]:<15} -> {ip}:{port}")
        results.append((label, ip, port))

    sock.close()
    print()

    if len(results) < 2:
        print("RESULT: inconclusive — fewer than two STUN servers answered.")
        print("Two servers at DIFFERENT addresses are required to tell a symmetric")
        print("NAT from a port-stable one. Check outbound UDP is not being filtered.")
        return 1

    ips = {r[1] for r in results}
    ports = {r[2] for r in results}

    if len(ports) == 1:
        print(f"RESULT: PORT-STABLE NAT (external {results[0][1]}:{results[0][2]})")
        print()
        print("The same external port is used toward every destination, so the")
        print("endpoint advertised to peers is the one they can actually punch.")
        print("Direct sessions should form. If peers are still relayed, the cause")
        print("is elsewhere — check LAN discovery and the peer's own NAT.")
        return 0

    print(f"RESULT: SYMMETRIC NAT (external IP {', '.join(sorted(ips))})")
    print(f"        external ports seen: {', '.join(str(p) for p in sorted(ports))}")
    print()
    print("This router hands out a new external port per destination. The single")
    print("endpoint discovered via STUN is therefore meaningless to a peer that is")
    print("itself behind a NAT: it punches at a port this router will never use for")
    print("that peer, the handshake never lands, and the two nodes fall back to")
    print("RELAYING through a mutual peer. Nodes with a stable listening endpoint")
    print("(a VPS, or a router with the port forwarded) still connect directly,")
    print("which is why only SOME peers look broken.")
    print()
    print("Fixes, most reliable first:")
    print("  1. Forward the overlay's UDP port on the router to this machine.")
    print("  2. Turn on NAT-PMP or PCP in the router — the client asks for a")
    print("     pinhole automatically (see client/portmap.go) and that bypasses")
    print("     the symmetric mapping entirely.")
    print("  3. Enable IPv6 on both ends. There is no NAT on v6, so peers reach")
    print("     each other directly (ipv6: true, on by default).")
    print("  4. Leave port prediction on. It sprays a spread of predicted ports")
    print("     and rescues the incremental-allocation case, but it cannot help")
    print("     a router that allocates ports randomly.")
    span = max(ports) - min(ports)
    print()
    print(f"        (observed port span across {len(results)} servers: {span} — a small,")
    print("         consistent step means prediction has a good chance; a large or")
    print("         erratic one means the allocation is random and it does not.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
