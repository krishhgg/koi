#!/usr/bin/env python3
"""Packet tests for the verification run network (docs/verify.md, "Run network").

Run as root on a box provisioned like the real one (host/cloud-init.sh, then
host/verify/install.sh), with koid stopped. run.sh is the driver; this file
does the work. Standard library only.

The test builds two run networks the way koid does: the same `docker network
create`, `docker create` and `docker network connect` arguments as
packages/daemon/src/docker.ts (networkArgs, recorderArgs, verifierArgs,
runArgs), the same addresses and MACs, and the same order of `apply` calls
through `sudo -n` as the koi user (VerificationNetwork.create, then reapply
after each container starts). The containers run a small stand-in image
instead of the recorder and the verifier, since what is tested is the network.

Probes run in a container's network namespace through nsenter, with this
file as the program. The firewall sees the same packets either way: it
filters on the bridge, by address, MAC and bridge port. The spoofing probes
run inside a deliberately privileged attacker container on the same bridge,
with its own capabilities.

Every denied flow has a listener on its target first, so a drop is told
apart from nothing listening. A flow counts as dropped when the client got
no answer, the listener saw nothing, and a deny rule's packet counter went
up. The output is one line per flow, with what was expected and what was
seen, and the exit code is 1 when any line does not match.

The same file is the probe program: `_listen`, `_connect` and the others
below run inside a namespace or a container and print JSON.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import selectors
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

HELPER = "/usr/local/libexec/koi-verify-net"
ENV_FILE = "/etc/koi/verify/env"
STATE_DIR = "/run/koi-verify"
PREVIEW_NETWORK = "koi-previews"
SLICE = "koi.slice"
APP_PORT = 8080
# runArgs gives a preview 3 CPUs, and Docker refuses more than the box has.
PREVIEW_CPUS = str(min(3, os.cpu_count() or 1))
# The base of the default verifier image (host/verifier/Dockerfile), so the
# stand-ins need nothing the box does not pull anyway.
BASE_IMAGE = "python:3.13.13-slim-bookworm@sha256:355bfa66770995d7e9a0da4b3473b44d0cb451f6b56f5615ad9c39e3c4eca03f"
STANDIN_IMAGE = "koi-packet-test:1"
TEST_LABEL = "koi.packet-test"
SELF = os.path.abspath(__file__)
PROBE_TIMEOUT = 2.0

# --- Probe side: runs inside a namespace or a container ---------------------------


def emit(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def probe_listen(args):
    """Listens on TCP and UDP ports and logs every connection and datagram as JSON lines until killed."""
    log = open(args.log, "a", buffering=1, encoding="utf-8")
    sel = selectors.DefaultSelector()
    family = socket.AF_INET6 if args.v6 else socket.AF_INET
    bind = args.bind or ("::" if args.v6 else "0.0.0.0")

    def note(**fields):
        log.write(json.dumps({"t": time.time(), **fields}) + "\n")

    for port in [int(p) for p in args.tcp.split(",") if p]:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if args.v6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind((bind, port))
        s.listen(64)
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ, ("accept", port))
    for port in [int(p) for p in args.udp.split(",") if p]:
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((bind, port))
        for entry in [g for g in (args.join or "").split(",") if g]:
            group, _, iface = entry.partition("@")
            mreq = struct.pack("4s4s", socket.inet_aton(group), socket.inet_aton(iface or "0.0.0.0"))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ, ("udp", port))
    emit({"ready": True})
    buffers = {}
    while True:
        for key, _ in sel.select():
            kind, port = key.data
            if kind == "accept":
                conn, peer = key.fileobj.accept()
                conn.setblocking(False)
                note(proto="tcp", port=port, peer=peer[0], event="accept")
                buffers[conn] = b""
                sel.register(conn, selectors.EVENT_READ, ("conn", port))
            elif kind == "udp":
                data, peer = key.fileobj.recvfrom(4096)
                note(proto="udp", port=port, peer=peer[0], data=data.decode(errors="replace"))
            else:
                conn = key.fileobj
                try:
                    chunk = conn.recv(4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    sel.unregister(conn)
                    conn.close()
                    buffers.pop(conn, None)
                    continue
                buffers[conn] += chunk
                while b"\n" in buffers[conn]:
                    line, buffers[conn] = buffers[conn].split(b"\n", 1)
                    peer = conn.getpeername()[0]
                    note(proto="tcp", port=port, peer=peer, data=line.decode(errors="replace"))
                    try:
                        conn.sendall(b"echo " + line + b"\n")
                    except OSError:
                        pass


def classify(err):
    if isinstance(err, socket.timeout) or isinstance(err, TimeoutError):
        return "timeout"
    if isinstance(err, ConnectionRefusedError):
        return "refused"
    if isinstance(err, OSError) and err.errno in (101, 113):
        return "unreachable"
    if isinstance(err, OSError) and err.errno in (1, 13):
        return "eperm"
    return f"error:{type(err).__name__}:{getattr(err, 'errno', '')}"


def probe_connect(args):
    """One TCP connection: open, send the token, wait for its echo."""
    family = socket.AF_INET6 if ":" in args.ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(args.timeout)
    if args.source:
        s.bind((args.source, 0))
    try:
        target = (args.ip, args.port, 0, socket.if_nametoindex(args.dev)) if args.dev else (args.ip, args.port)
        s.connect(target)
    except OSError as err:
        emit({"result": classify(err)})
        return
    try:
        s.sendall(args.token.encode() + b"\n")
        data = s.recv(4096).decode(errors="replace")
    except OSError as err:
        emit({"result": "open", "echo": None, "after": classify(err)})
        return
    emit({"result": "open", "echo": data.strip()})


def probe_udp(args):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if args.ttl:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, args.ttl)
    if args.iface_ip:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(args.iface_ip))
    try:
        s.sendto(args.token.encode(), (args.ip, args.port))
    except OSError as err:
        emit({"result": classify(err)})
        return
    emit({"result": "sent"})


def dns_query(name, qtype=1):
    header = struct.pack("!HHHHHH", secrets.randbits(16), 0x0100, 1, 0, 0, 0)
    question = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return header + question + struct.pack("!HH", qtype, 1)


def probe_dns(args):
    """One DNS query for a unique name; answer, timeout or error."""
    query = dns_query(args.name)
    try:
        if args.tcp:
            s = socket.create_connection((args.server, 53), timeout=args.timeout)
            s.sendall(struct.pack("!H", len(query)) + query)
            data = s.recv(4096)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(args.timeout)
            s.sendto(query, (args.server, 53))
            data, _ = s.recvfrom(4096)
    except OSError as err:
        emit({"result": classify(err)})
        return
    rcode = data[3 + (2 if args.tcp else 0)] & 0x0F if len(data) > 4 else None
    emit({"result": "answer", "rcode": rcode})


def probe_http(args):
    """An HTTP request with the stdlib client, for the metadata service and the internet."""
    import http.client

    conn = http.client.HTTPConnection(args.ip, args.port, timeout=args.timeout)
    headers = {}
    if args.method == "PUT":
        headers["X-aws-ec2-metadata-token-ttl-seconds"] = "60"
    try:
        conn.request(args.method, args.path, headers=headers)
        status = conn.getresponse().status
    except OSError as err:
        emit({"result": classify(err)})
        return
    emit({"result": "answer", "status": status})


def probe_ping(args):
    """One ICMP echo with a datagram socket, IPv4."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    s.settimeout(args.timeout)
    if args.iface_ip:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(args.iface_ip))
    body = struct.pack("!BBHHH", 8, 0, 0, 0, 1) + b"koi-packet-test"
    try:
        s.sendto(body, (args.ip, 0))
        s.recvfrom(1024)
    except OSError as err:
        emit({"result": classify(err)})
        return
    emit({"result": "answer"})


def probe_hold(args):
    """A connection kept open: echo once, then once more for each line on stdin."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(args.timeout)
    try:
        s.connect((args.ip, args.port))
        s.sendall(b"hold-1\n")
        first = s.recv(4096).decode(errors="replace").strip()
    except OSError as err:
        emit({"stage": "open", "result": classify(err)})
        return
    emit({"stage": "open", "result": "open", "echo": first})
    for line in sys.stdin:
        token = line.strip()
        try:
            s.sendall(token.encode() + b"\n")
            reply = s.recv(4096).decode(errors="replace").strip()
            emit({"stage": token, "result": "echo" if reply else "closed", "echo": reply})
        except OSError as err:
            emit({"stage": token, "result": classify(err)})


def probe_rawcheck(args):
    """What a container's own process may do with raw sockets: each attempt and its error."""
    out = {}
    tries = {
        "packet": (socket.AF_PACKET, socket.SOCK_RAW, 0x0300),
        "raw_tcp": (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP),
        "raw_ip": (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW),
    }
    for name, (family, kind, proto) in tries.items():
        try:
            socket.socket(family, kind, proto).close()
            out[name] = "allowed"
        except OSError as err:
            out[name] = "eperm" if err.errno in (1, 13) else f"errno {err.errno}"
    with open("/proc/self/status", encoding="ascii") as f:
        for line in f:
            if line.startswith("CapEff:"):
                out["CapEff"] = line.split()[1]
    emit(out)


# --- Frames, for the attacker container -------------------------------------------


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def mac_bytes(mac):
    return bytes(int(b, 16) for b in mac.split(":"))


# What goes between the MACs and the IPv4 packet. VLAN id 0 is a priority
# tag, which the receiving kernel strips. qinq and adq are two tags (802.1Q
# twice, or 802.1ad outside 802.1Q), which br_netfilter never hands to
# iptables whatever its sysctls say. pppoe is a PPPoE session frame.
ENCAPS = {
    "": b"",
    "vlan0": struct.pack("!HH", 0x8100, 0),
    "qinq": struct.pack("!HHHH", 0x8100, 0, 0x8100, 0),
    "adq": struct.pack("!HHHH", 0x88A8, 0, 0x8100, 0),
}


def frame(src_mac, dst_mac, src_ip, dst_ip, proto, payload, encap=""):
    """An Ethernet frame holding one IPv4 packet, under the tags or the PPPoE header `encap` names."""
    ip_header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), secrets.randbits(16), 0x4000, 64, proto, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
    eth = mac_bytes(dst_mac) + mac_bytes(src_mac)
    if encap == "pppoe":
        packet = ip_header + payload
        # Version and type 1, session 1, the PPP protocol for IPv4.
        return eth + struct.pack("!HBBHHH", 0x8864, 0x11, 0, 1, len(packet) + 2, 0x0021) + packet
    return eth + ENCAPS[encap] + struct.pack("!H", 0x0800) + ip_header + payload


def l4_checksum(src_ip, dst_ip, proto, segment):
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, proto, len(segment))
    return checksum(pseudo + segment)


def tcp_syn(src_ip, dst_ip, sport, dport):
    seg = struct.pack("!HHIIBBHHH", sport, dport, secrets.randbits(32), 0, 5 << 4, 0x02, 64240, 0, 0)
    csum = l4_checksum(src_ip, dst_ip, 6, seg)
    return seg[:16] + struct.pack("!H", csum) + seg[18:]


def udp_datagram(src_ip, dst_ip, sport, dport, data):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    csum = l4_checksum(src_ip, dst_ip, 17, seg) or 0xFFFF
    return seg[:6] + struct.pack("!H", csum) + seg[8:]


def parse_ipv4(raw):
    """(src, dst, proto, l4 bytes) of a frame carrying IPv4, under any number of VLAN tags or none, else None."""
    ethertype = struct.unpack("!H", raw[12:14])[0]
    offset = 14
    while ethertype in (0x8100, 0x88A8) and len(raw) >= offset + 4:
        ethertype = struct.unpack("!H", raw[offset + 2: offset + 4])[0]
        offset += 4
    if ethertype != 0x0800 or len(raw) < offset + 20:
        return None
    ihl = (raw[offset] & 0x0F) * 4
    proto = raw[offset + 9]
    src = socket.inet_ntoa(raw[offset + 12: offset + 16])
    dst = socket.inet_ntoa(raw[offset + 16: offset + 20])
    return src, dst, proto, raw[offset + ihl:]


def packet_socket(dev):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((dev, 0))
    s.settimeout(0.2)
    return s


def probe_forge(args):
    """Sends forged SYNs (or a UDP datagram) from the attacker's port and says whether the target answered."""
    s = packet_socket(args.dev)
    sport = 40000 + secrets.randbelow(20000)
    if args.udp:
        payload = udp_datagram(args.src_ip, args.dst_ip, sport, args.dport, args.token.encode())
        proto = 17
    else:
        payload = tcp_syn(args.src_ip, args.dst_ip, sport, args.dport)
        proto = 6
    raw = frame(args.src_mac, args.dst_mac, args.src_ip, args.dst_ip, proto, payload, encap=args.encap)
    synack = False
    deadline = time.time() + args.timeout
    sent = 0
    while time.time() < deadline:
        if sent < 3:
            s.send(raw)
            sent += 1
        try:
            got = s.recv(65535)
        except socket.timeout:
            continue
        parsed = parse_ipv4(got)
        if parsed is None or args.udp:
            continue
        src, dst, p, l4 = parsed
        if p == 6 and src == args.dst_ip and dst == args.src_ip and len(l4) >= 14:
            ports = struct.unpack("!HH", l4[:4])
            if ports == (args.dport, sport) and l4[13] & 0x12 == 0x12:
                synack = True
                break
    emit({"sent": sent, "synack": synack})


def arp_frame(own_mac, victim_mac, victim_ip, claim_ip, op):
    """An ARP request (op 1) or reply (op 2) to the victim, saying `claim_ip` is at `own_mac`."""
    target_mac = b"\0" * 6 if op == 1 else mac_bytes(victim_mac)
    return (mac_bytes(victim_mac) + mac_bytes(own_mac) + struct.pack("!H", 0x0806)
            + struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mac_bytes(own_mac) + socket.inet_aton(claim_ip)
            + target_mac + socket.inet_aton(victim_ip))


def probe_intercept(args):
    """Tries to get frames carrying `marker` sent to this port, then watches for them.

    With --poison, teaches the bridge that that MAC is on this port, with
    frames from it, ARP among them. With --victim-mac, --victim-ip and
    --claim, tells the victim that the claimed address is at this
    interface's own MAC, with ARP requests and replies.
    """
    s = packet_socket(args.dev)
    lures = []
    if args.poison:
        poison = mac_bytes(args.poison)
        # A frame of a local experimental ethertype, broadcast, from the poisoned MAC.
        lures.append(b"\xff" * 6 + poison + struct.pack("!H", 0x88B5) + b"koi-packet-test".ljust(46, b"\0"))
        # And a gratuitous ARP from it, which iptables never sees.
        lures.append(b"\xff" * 6 + poison + struct.pack("!H", 0x0806) + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
                     + poison + socket.inet_aton(args.poison_ip) + b"\0" * 6 + socket.inet_aton(args.poison_ip))
    if args.claim:
        with open(f"/sys/class/net/{args.dev}/address", encoding="ascii") as f:
            own = f.read().strip()
        for op in (1, 2):
            lures.append(arp_frame(own, args.victim_mac, args.victim_ip, args.claim, op))
    deadline = time.time() + args.seconds
    found = None
    last = 0.0
    emit({"ready": True})
    while time.time() < deadline and found is None:
        if time.time() - last > 0.05:
            for lure in lures:
                s.send(lure)
            last = time.time()
        try:
            got = s.recv(65535)
        except socket.timeout:
            continue
        if args.marker.encode() in got:
            parsed = parse_ipv4(got)
            found = {"dst_mac": got[0:6].hex(":"), "src": parsed[0] if parsed else None, "dst": parsed[1] if parsed else None}
    emit({"intercepted": found is not None, "frame": found})


def probe_main(argv):
    p = argparse.ArgumentParser(prog="packets.py probe")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("_listen")
    a.add_argument("log")
    a.add_argument("--tcp", default="")
    a.add_argument("--udp", default="")
    a.add_argument("--join", default="")
    a.add_argument("--bind", default="")
    a.add_argument("--v6", action="store_true")
    a = sub.add_parser("_connect")
    a.add_argument("ip")
    a.add_argument("port", type=int)
    a.add_argument("token")
    a.add_argument("--timeout", type=float, default=PROBE_TIMEOUT)
    a.add_argument("--dev", default="")
    a.add_argument("--source", default="")
    a = sub.add_parser("_udp")
    a.add_argument("ip")
    a.add_argument("port", type=int)
    a.add_argument("token")
    a.add_argument("--ttl", type=int, default=0)
    a.add_argument("--iface-ip", dest="iface_ip", default="")
    a = sub.add_parser("_dns")
    a.add_argument("server")
    a.add_argument("name")
    a.add_argument("--tcp", action="store_true")
    a.add_argument("--timeout", type=float, default=PROBE_TIMEOUT)
    a = sub.add_parser("_http")
    a.add_argument("ip")
    a.add_argument("port", type=int)
    a.add_argument("method")
    a.add_argument("path")
    a.add_argument("--timeout", type=float, default=PROBE_TIMEOUT)
    a = sub.add_parser("_ping")
    a.add_argument("ip")
    a.add_argument("--timeout", type=float, default=PROBE_TIMEOUT)
    a.add_argument("--iface-ip", dest="iface_ip", default="")
    a = sub.add_parser("_hold")
    a.add_argument("ip")
    a.add_argument("port", type=int)
    a.add_argument("--timeout", type=float, default=PROBE_TIMEOUT)
    sub.add_parser("_rawcheck")
    a = sub.add_parser("_forge")
    for name in ("src_ip", "src_mac", "dst_ip", "dst_mac"):
        a.add_argument("--" + name.replace("_", "-"), dest=name, required=True)
    a.add_argument("--dport", type=int, required=True)
    a.add_argument("--dev", default="eth0")
    a.add_argument("--udp", action="store_true")
    a.add_argument("--encap", choices=["", "pppoe", *ENCAPS], default="")
    a.add_argument("--token", default="koi-forged")
    a.add_argument("--timeout", type=float, default=PROBE_TIMEOUT)
    a = sub.add_parser("_intercept")
    a.add_argument("--poison", default="")
    a.add_argument("--poison-ip", dest="poison_ip", default="0.0.0.0")
    a.add_argument("--victim-mac", dest="victim_mac", default="")
    a.add_argument("--victim-ip", dest="victim_ip", default="")
    a.add_argument("--claim", default="")
    a.add_argument("--marker", required=True)
    a.add_argument("--seconds", type=float, default=6.0)
    a.add_argument("--dev", default="eth0")
    args = p.parse_args(argv)
    {
        "_listen": probe_listen, "_connect": probe_connect, "_udp": probe_udp, "_dns": probe_dns,
        "_http": probe_http, "_ping": probe_ping, "_hold": probe_hold, "_rawcheck": probe_rawcheck,
        "_forge": probe_forge, "_intercept": probe_intercept,
    }[args.cmd](args)


# --- Host side ---------------------------------------------------------------------


class Abort(Exception):
    """A step the rest of the test depends on failed."""


def run(argv, stdin=None, check=True, timeout=120):
    done = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout)
    if check and done.returncode != 0:
        raise Abort(f"{' '.join(argv[:6])} exited {done.returncode}: {(done.stderr or done.stdout).strip()[-400:]}")
    return done


def docker(*args, check=True, stdin=None):
    return run(["docker", *args], check=check, stdin=stdin)


def helper(*args, stdin=None):
    """The helper as koid runs it: as koi, through sudo -n."""
    return run(["runuser", "-u", "koi", "--", "sudo", "-n", HELPER, *args], stdin=stdin, check=False)


def read_pool():
    with open(ENV_FILE, encoding="utf-8") as f:
        for line in f:
            key, _, value = line.strip().partition("=")
            if key == "KOI_VERIFY_POOL":
                return ipaddress.ip_network(value.strip().strip("'\""))
    raise Abort(f"no KOI_VERIFY_POOL in {ENV_FILE}")


def bridge_name(run_id):
    """kv and 12 hex digits, as koid names a run's bridge (verification-network.ts, bridgeName)."""
    return "kv" + hashlib.sha256(f"{run_id}:0".encode()).hexdigest()[:12]


def helper_mac(ip):
    """02:4b and the address's four bytes (verification-network.ts, helperMac)."""
    return "02:4b:" + ":".join(f"{int(o):02x}" for o in ip.split("."))


def pid_of(name):
    return int(docker("inspect", "--format", "{{.State.Pid}}", name).stdout.strip())


def endpoint_of(name, network):
    nets = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", name).stdout)
    entry = nets.get(network) or {}
    return entry.get("IPAddress"), entry.get("MacAddress")


def ns_argv(name):
    return ["nsenter", f"--net=/proc/{pid_of(name)}/ns/net", "--"]


def in_ns(name, *probe, stdin=None, timeout=30):
    """A probe in a container's network namespace, run by this host's python3; its JSON result."""
    done = run([*ns_argv(name), sys.executable, "-I", SELF, *probe], stdin=stdin, check=False, timeout=timeout)
    return last_json(done)


def in_container(name, *probe, timeout=30):
    """A probe run by the container's own python3, as the container's user with its capabilities."""
    with open(SELF, encoding="utf-8") as f:
        source = f.read()
    done = run(["docker", "exec", "-i", name, "python3", "-I", "-", *probe], stdin=source, check=False, timeout=timeout)
    return last_json(done)


def last_json(done):
    for line in reversed(done.stdout.splitlines()):
        try:
            return json.loads(line)
        except ValueError:
            continue
    return {"result": "error", "stderr": done.stderr.strip()[-300:], "code": done.returncode}


def ip_in(name, *args):
    return run([*ns_argv(name), "ip", *args], check=False)


# Counters ---------------------------------------------------------------------------

COUNTED_CHAINS = re.compile(r"^(KOI-VERIFY\S*|DOCKER-USER|INPUT|OUTPUT|FORWARD)$")


def counters():
    """Packet counters of every rule in the chains that guard kv+ bridges, IPv4 and IPv6."""
    found = {}
    for tool, family in (("iptables-save", "v4"), ("ip6tables-save", "v6")):
        text = run([tool, "-c", "-t", "filter"]).stdout
        seen = {}
        for line in text.splitlines():
            m = re.match(r"^\[(\d+):(\d+)\] -A (\S+) (.*)$", line)
            if not m or not COUNTED_CHAINS.match(m.group(3)):
                continue
            key = (family, m.group(3), m.group(4))
            seen[key] = seen.get(key, 0) + 1
            found[(*key, seen[key])] = int(m.group(1))
    return found


def rose(before, after, deny_only=True):
    """The rules whose counters went up, as short text, denies first."""
    out = []
    for key, value in after.items():
        delta = value - before.get(key, 0)
        if delta <= 0:
            continue
        family, chain, rule, _ = key
        if family == "v4" and chain in ("INPUT", "OUTPUT", "FORWARD", "DOCKER-USER") and "KOI-VERIFY" in rule:
            continue
        if deny_only and not rule.endswith("-j DROP"):
            continue
        out.append(f"{'' if family == 'v4' else 'ip6 '}{chain} [{rule}] +{delta}")
    return out


def permits_rose(before, after, run_id):
    return [
        f"{chain} +{after[key] - before.get(key, 0)}"
        for key in after
        if (chain := key[1]) and f"koi-run={run_id}" in key[2] and after[key] > before.get(key, 0)
    ]


# Listeners --------------------------------------------------------------------------


class Listener:
    """A probe listener in a namespace (or on the host), logging to a file this side reads."""

    def __init__(self, work, label, container, tcp=(), udp=(), join="", bind="", v6=False):
        self.label = label
        self.path = os.path.join(work, f"listen-{label}.log")
        open(self.path, "w").close()
        argv = [sys.executable, "-I", SELF, "_listen", self.path,
                "--tcp", ",".join(map(str, tcp)), "--udp", ",".join(map(str, udp))]
        if join:
            argv += ["--join", join]
        if bind:
            argv += ["--bind", bind]
        if v6:
            argv.append("--v6")
        if container is not None:
            argv = ns_argv(container) + argv
        self.proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = self.proc.stdout.readline()
        if '"ready"' not in line:
            raise Abort(f"listener {label} did not start: {self.proc.stderr.read()[-400:]}")

    def events(self, since):
        with open(self.path, encoding="utf-8") as f:
            return [e for e in (json.loads(line) for line in f if line.strip()) if e["t"] >= since]

    def stop(self):
        self.proc.kill()
        self.proc.wait()


# --- The test --------------------------------------------------------------------------


class Report:
    """One line per check. GAP marks a documented limit that was seen: it is printed and does not fail the run."""

    def __init__(self):
        self.lines = []
        self.failed = 0
        self.gaps = 0

    def add(self, name, expected, observed, ok, how, known=False):
        status = "PASS" if ok else ("GAP " if known else "FAIL")
        if not ok and known:
            self.gaps += 1
        elif not ok:
            self.failed += 1
        line = f"{status}  {name:<58} expected={expected:<8} observed={observed:<10} {how}"
        self.lines.append(line)
        print(line, flush=True)

    def note(self, text):
        print(f"      {text}", flush=True)


class Run:
    """One run network as koid builds it, with stand-ins for the recorder and the verifier."""

    def __init__(self, run_id, subnet, app):
        self.id = run_id
        self.subnet = subnet
        self.network = f"koi-v-{run_id}"
        self.bridge = bridge_name(run_id)
        hosts = list(subnet.hosts())
        self.gateway, self.app_ip, self.recorder_ip, self.verifier_ip = (str(h) for h in hosts[:4])
        self.app = app
        self.recorder = f"koi-verify-{run_id}-recorder"
        self.verifier = f"koi-verify-{run_id}-verifier"
        self.app_mac = None

    def descriptor(self, **override):
        endpoints = [
            {"role": "app", "container": self.app, "ip": self.app_ip, "mac": self.app_mac},
            {"role": "recorder", "container": self.recorder, "ip": self.recorder_ip, "mac": helper_mac(self.recorder_ip)},
            {"role": "verifier", "container": self.verifier, "ip": self.verifier_ip, "mac": helper_mac(self.verifier_ip)},
        ]
        desc = {"version": 1, "runId": self.id, "bridge": self.bridge, "subnet": str(self.subnet),
                "appPort": APP_PORT, "endpoints": endpoints}
        desc.update(override)
        return json.dumps(desc) + "\n"

    def helper_args(self, role, ip):
        """docker create for a helper: helperArgs and the role's own flags in docker.ts, with the stand-in image."""
        common = [
            "--name", f"koi-verify-{self.id}-{role}", "--network", self.network, "--ip", ip,
            "--mac-address", helper_mac(ip),
        ]
        if role == "recorder":
            limits = ["--user", "10001:10001", "--read-only", "--cap-drop", "ALL", "--security-opt",
                      "no-new-privileges=true", "--ipc", "private", "--init", "--memory", "2g", "--memory-swap", "2g",
                      "--cpus", "1.5", "--pids-limit", "512", "--ulimit", "nofile=4096:4096", "--ulimit", "core=0:0"]
        else:
            limits = ["--user", "10002:10002", "--read-only", "--cap-drop", "ALL", "--security-opt",
                      "no-new-privileges=true", "--ipc", "private", "--init", "--memory", "1g", "--memory-swap", "1g",
                      "--cpus", "1", "--pids-limit", "256", "--ulimit", "nofile=4096:4096", "--ulimit", "core=0:0"]
        args = ["create", *common, *limits, "--restart", "no", "--stop-timeout", "10", "--log-driver", "none",
                "--dns", self.gateway, "--add-host", f"app.{self.id}.invalid:{self.app_ip}",
                "--label", "koi.preview=", "--label", f"koi.role={role}", "--label", f"koi.run={self.id}",
                "--label", f"{TEST_LABEL}=1"]
        if slice_exists():
            args += ["--cgroup-parent", SLICE]
        args += ["--env", f"KOI_RUN_ID={self.id}", "--env", f"KOI_PREVIEW_URL=http://app.{self.id}.invalid:{APP_PORT}"]
        if role == "recorder":
            args += ["--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=512m,uid=10001,gid=10001", "--shm-size", "256m"]
        else:
            args += ["--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=256m,uid=10002,gid=10002",
                     "--tmpfs", "/work:rw,nosuid,nodev,noexec,size=128m,uid=10002,gid=10002", "--interactive"]
        args.append(STANDIN_IMAGE)
        return args


_slice = None


def read_sysctl(name):
    try:
        with open("/proc/sys/" + name.replace(".", "/"), encoding="ascii") as f:
            return f.read().strip()
    except OSError:
        return None


def slice_exists():
    global _slice
    if _slice is None:
        _slice = run(["systemctl", "is-active", "--quiet", SLICE], check=False).returncode == 0
    return _slice


def preview_args(name, label):
    """docker run for a preview: runArgs in docker.ts, with the stand-in image."""
    args = ["run", "--detach", "--name", name, "--network", PREVIEW_NETWORK, "--user", "65534:65534",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "2048", "--memory", "6g",
            "--memory-swap", "6g", "--cpus", PREVIEW_CPUS, "--restart", "no", "--log-opt", "max-size=10m", "--log-opt",
            "max-file=3", "--label", "koi.role="]
    if slice_exists():
        args += ["--cgroup-parent", SLICE]
    args += ["--label", f"koi.preview={label}", "--label", f"{TEST_LABEL}=1", STANDIN_IMAGE]
    return args


def build_standin():
    work = tempfile.mkdtemp(prefix="koi-packet-test-image-")
    try:
        with open(os.path.join(work, "Dockerfile"), "w", encoding="utf-8") as f:
            f.write(
                f"FROM {BASE_IMAGE}\n"
                "# Sleeps until stopped; the probes run in its network namespace.\n"
                'ENTRYPOINT ["python3", "-c", "import signal; signal.pause()"]\n'
            )
        docker("build", "--quiet", "-t", STANDIN_IMAGE, work)
    finally:
        shutil.rmtree(work)


def cleanup(runs_known=()):
    """Removes everything a packet test made, this one or an earlier one that stopped part way."""
    states = []
    if os.path.isdir(STATE_DIR):
        states = [n[:-5] for n in os.listdir(STATE_DIR) if n.startswith("pkt") and n.endswith(".json")]
    for run_id in sorted(set(states) | set(runs_known)):
        helper("revoke", run_id)
    names = docker("ps", "-aq", "--filter", f"label={TEST_LABEL}").stdout.split()
    if names:
        docker("rm", "--force", *names, check=False)
    nets = docker("network", "ls", "-q", "--filter", f"label={TEST_LABEL}").stdout.split()
    for net in nets:
        docker("network", "rm", net, check=False)


def free_subnets(pool, count):
    """The highest /28s of the pool no Docker network and no helper state holds; koid allocates lowest first."""
    used = []
    for net_id in docker("network", "ls", "-q").stdout.split():
        info = json.loads(docker("network", "inspect", "--format", "{{json .IPAM.Config}}", net_id).stdout or "null") or []
        used += [ipaddress.ip_network(c["Subnet"]) for c in info if c.get("Subnet") and ":" not in c["Subnet"]]
    if os.path.isdir(STATE_DIR):
        for name in os.listdir(STATE_DIR):
            try:
                with open(os.path.join(STATE_DIR, name), encoding="utf-8") as f:
                    used.append(ipaddress.ip_network(json.load(f)["subnet"]))
            except (OSError, ValueError, KeyError):
                continue
    found = []
    for candidate in reversed(list(pool.subnets(new_prefix=28))):
        if not any(candidate.overlaps(u) for u in used):
            found.append(candidate)
        if len(found) == count:
            return found
    raise Abort(f"the pool {pool} has no {count} free /28s")


class PacketTest:
    def __init__(self, keep, verbose):
        self.keep = keep
        self.verbose = verbose
        self.report = Report()
        self.work = tempfile.mkdtemp(prefix="koi-packet-test-")
        # Probes that run as koi or nobody on the host need a copy they can read.
        os.chmod(self.work, 0o755)
        self.probe = os.path.join(self.work, "probe.py")
        shutil.copyfile(SELF, self.probe)
        os.chmod(self.probe, 0o644)
        self.listeners = []
        self.runs = []

    # Steps ---------------------------------------------------------------------------

    def check(self, name, expected, observed, how, known=False):
        self.report.add(name, expected, observed, expected == observed, how, known)

    def facts(self):
        """What the result depends on: kernel, Docker, the iptables backend and the bridge sysctls."""
        docker_version = docker("version", "--format", "{{.Server.Version}}", check=False).stdout.strip()
        iptables_version = run(["iptables", "--version"], check=False).stdout.strip()
        sysctls = {name: read_sysctl(name) for name in (
            "net.bridge.bridge-nf-call-iptables", "net.bridge.bridge-nf-call-ip6tables",
            "net.bridge.bridge-nf-filter-vlan-tagged", "net.bridge.bridge-nf-filter-pppoe-tagged")}
        self.report.note(f"kernel {os.uname().release}; docker {docker_version}; {iptables_version}")
        self.report.note("sysctls " + " ".join(f"{k.split('.')[-1]}={v}" for k, v in sysctls.items()))

    def prerequisites(self):
        if os.geteuid() != 0:
            raise Abort("run as root")
        self.facts()
        for tool in ("docker", "iptables-save", "ip6tables-save", "ebtables", "ebtables-save", "bridge", "nsenter",
                     "conntrack", "tcpdump", "sudo", "runuser"):
            if shutil.which(tool) is None:
                raise Abort(f"{tool} is not installed")
        if not os.path.exists(HELPER):
            raise Abort(f"{HELPER} is not installed; run host/verify/install.sh")
        if run(["systemctl", "is-active", "--quiet", "koid"], check=False).returncode == 0:
            raise Abort("koid is running; stop it first (systemctl stop koid), since koid cleans up run networks it did not make")
        self.pool = read_pool()
        attest = helper("attest")
        self.check("helper attest through sudo as koi", "ok", "ok" if attest.returncode == 0 else f"exit{attest.returncode}",
                   (attest.stderr or "").strip()[-200:] or "sudo -n koi-verify-net attest")
        if attest.returncode != 0:
            raise Abort("the helper does not attest")

    def provision_twice(self):
        def ruleset():
            text = run(["iptables-save"]).stdout + run(["ip6tables-save"]).stdout + run(["ebtables-save"]).stdout
            return [re.sub(r"\[\d+:\d+\]", "", line) for line in text.splitlines() if not line.startswith("#")]

        before = ruleset()
        first = run([HELPER, "provision"], check=False)
        middle = ruleset()
        second = run([HELPER, "provision"], check=False)
        after = ruleset()
        ok = first.returncode == 0 and second.returncode == 0
        changed = []
        if second.returncode == 0:
            changed = json.loads(second.stdout).get("changed", [])
        same = middle == after
        observed = "same" if ok and same and not changed else ("failed" if not ok else "changed")
        how = (f"exit {first.returncode} then {second.returncode}; second changed {changed}; "
               f"ruleset {'unchanged' if same else 'changed'}")
        if not ok:
            how += "; " + ((second.stderr or first.stderr).strip()[-200:])
        self.check("provision run twice leaves the ruleset as it was", "same", observed, how)
        if before != middle and self.verbose:
            self.report.note("the first provision changed the ruleset (expected on a box that never ran it)")

    def make_preview(self, name, label):
        docker(*preview_args(name, label))
        return name

    def make_run(self, run_id, subnet, app):
        r = Run(run_id, subnet, app)
        docker("network", "create", "--driver", "bridge", "--internal", "--ipv6=false", "--subnet", str(subnet),
               "--gateway", r.gateway, "--opt", "com.docker.network.bridge.enable_icc=false",
               "--opt", "com.docker.network.bridge.enable_ip_masquerade=false",
               "--opt", f"com.docker.network.bridge.name={r.bridge}", "--label", f"koi.run={run_id}",
               "--label", f"{TEST_LABEL}=1", r.network)
        docker("network", "connect", "--ip", r.app_ip, r.network, app)
        ip, mac = endpoint_of(app, r.network)
        if ip != r.app_ip or not mac:
            raise Abort(f"{app} got {ip} {mac} on {r.network}")
        r.app_mac = mac
        docker(*r.helper_args("recorder", r.recorder_ip))
        docker(*r.helper_args("verifier", r.verifier_ip))
        self.runs.append(r)
        return r

    def apply(self, r, label, bound=()):
        done = helper("apply", stdin=r.descriptor())
        if done.returncode != 0:
            self.check(f"{label}: apply through sudo as koi", "ok", f"exit{done.returncode}", done.stderr.strip()[-300:])
            raise Abort(f"apply of {r.id} failed")
        attest = json.loads(helper("attest").stdout)
        ports = (attest.get("ports") or {}).get(r.id) or {}
        problems = attest["ipv4"]["problems"] + attest["ipv6"]["problems"] + (attest.get("bridge") or {}).get("problems", [])
        bad = [role for role in bound if not isinstance(ports.get(role), str)]
        ok = r.id in attest["runs"] and not problems and not bad
        self.check(f"{label}: apply, attest lists the run, ports bound {list(bound) or 'none'}", "ok",
                   "ok" if ok else "bad", f"ports={ports} problems={problems[:2]}")
        return ports

    def start(self, name):
        docker("start", name)

    def setup(self):
        self.report.note("building the stand-in image and the two runs")
        build_standin()
        a_net, b_net = free_subnets(self.pool, 2)
        token = secrets.token_hex(6)
        self.app_a = self.make_preview(f"koi-pkt{token}a-app", f"pkt-{token}-a")
        self.app_b = self.make_preview(f"koi-pkt{token}b-app", f"pkt-{token}-b")
        self.other = self.make_preview(f"koi-pkt{token}c-app", f"pkt-{token}-c")
        self.a = self.make_run(f"pkt{token}a{secrets.token_hex(4)}", a_net, self.app_a)
        self.b = self.make_run(f"pkt{token}b{secrets.token_hex(4)}", b_net, self.app_b)
        a, b = self.a, self.b
        # The attacker: privileged on purpose, on run A's bridge, at .10.
        self.attacker_ip = str(list(a.subnet.hosts())[9])
        self.attacker_mac = "02:66:" + ":".join(f"{int(o):02x}" for o in self.attacker_ip.split("."))
        docker("run", "--detach", "--name", f"koi-pkt{token}-attacker", "--network", a.network, "--ip",
               self.attacker_ip, "--mac-address", self.attacker_mac, "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",
               "--label", f"{TEST_LABEL}=1", STANDIN_IMAGE)
        self.attacker = f"koi-pkt{token}-attacker"
        self.report.note(f"run A {a.id} {a.subnet} bridge {a.bridge}; run B {b.id} {b.subnet} bridge {b.bridge}")
        # koid's order: apply with nothing running, then the recorder starts and
        # the permits bind to its port, then each verifier.
        self.apply(a, "run A, nothing started")
        self.apply(b, "run B, nothing started")
        self.start(a.recorder)
        self.apply(a, "run A, recorder started", bound=["recorder"])
        self.start(b.recorder)
        self.apply(b, "run B, recorder started", bound=["recorder"])

    def start_verifiers(self):
        for r, label in ((self.a, "run A"), (self.b, "run B")):
            self.start(r.verifier)
            self.apply(r, f"{label}, verifier started", bound=["recorder", "verifier"])

    def listen(self, *args, **kwargs):
        listener = Listener(self.work, *args, **kwargs)
        self.listeners.append(listener)
        return listener

    def listeners_up(self):
        """Listeners in everything that runs before the verifiers start."""
        a, b = self.a, self.b
        L = self.listen
        self.l_app = L("app-a", a.app, tcp=[APP_PORT, 8081, 22, 4317], udp=[5353, 9999], join=f"224.0.0.251@{a.app_ip}")
        self.l_rec = L("recorder-a", a.recorder, tcp=[4317, 4318, 9222, 22, 80, APP_PORT], udp=[9999])
        self.l_app_b = L("app-b", b.app, tcp=[APP_PORT])
        self.l_rec_b = L("recorder-b", b.recorder, tcp=[4317, 4318])
        self.l_other = L("other-preview", self.other, tcp=[APP_PORT])
        self.l_host = L("host", None, tcp=[18080], udp=[18081])
        self.l_dns = [L(f"dns-{r.id[:10]}", None, tcp=[53], udp=[53], bind=r.gateway) for r in (a, b)]
        # The egress proxy's port on the preview bridge, where the app's own
        # path out must still work. The real proxy may already listen there.
        self.l_proxy = None
        gw = self.preview_gateway()
        if run(["ss", "-Htln", "sport", "=", ":3128"], check=False).stdout.strip() == "":
            self.l_proxy = L("proxy", None, tcp=[3128], bind=gw)

    def verifier_listeners_up(self):
        self.l_ver = self.listen("verifier-a", self.a.verifier, tcp=[APP_PORT, 9000, 4317], udp=[9999])
        self.l_ver_b = self.listen("verifier-b", self.b.verifier, tcp=[9000])

    def preview_gateway(self):
        cfg = json.loads(docker("network", "inspect", "--format", "{{json .IPAM.Config}}", PREVIEW_NETWORK).stdout)
        gw = cfg[0].get("Gateway")
        if not gw:
            gw = str(next(ipaddress.ip_network(cfg[0]["Subnet"]).hosts()))
        return gw

    def preview_ip(self, name):
        return endpoint_of(name, PREVIEW_NETWORK)[0]

    # Probes --------------------------------------------------------------------------

    def tcp(self, name, src, dst_ip, port, expect, listener, permit_run=None):
        """One TCP flow from container `src` (None: the host as root; ("user", u): the host as u)."""
        tok = f"pkt-{secrets.token_hex(4)}"
        before = counters()
        since = time.time()
        if src is None:
            result = last_json(run([sys.executable, "-I", self.probe, "_connect", dst_ip, str(port), tok], check=False))
        elif isinstance(src, tuple):
            result = last_json(run(["runuser", "-u", src[1], "--", sys.executable, "-I", self.probe, "_connect", dst_ip,
                                    str(port), tok], check=False))
        else:
            result = in_ns(src, "_connect", dst_ip, str(port), tok)
        time.sleep(0.3)
        after = counters()
        seen = [e for e in listener.events(since) if e.get("port") == port] if listener else []
        drops = rose(before, after)
        permits = permits_rose(before, after, permit_run) if permit_run else []
        res = result.get("result")
        if res == "open" and result.get("echo") == f"echo {tok}" and any(e.get("data") == tok for e in seen):
            observed = "open"
        elif res in ("timeout", "unreachable", "eperm") and not seen and drops:
            observed = "dropped"
        elif res in ("timeout", "unreachable", "eperm") and not seen:
            observed = "no-answer"
        else:
            observed = res or "error"
        how = f"client {res}"
        if listener is not None:
            how += f"; listener saw {len(seen)}"
        if observed == "open" and permits:
            how += f"; permits {', '.join(permits)}"
        if drops:
            how += f"; {'; '.join(drops[:2])}"
        if result.get("stderr"):
            how += f"; {result['stderr']}"
        self.check(name, expect, observed, how)
        return observed

    def udp(self, name, src, dst_ip, port, listener, ttl=0, iface_ip=""):
        tok = f"pkt-{secrets.token_hex(4)}"
        before = counters()
        since = time.time()
        args = ["_udp", dst_ip, str(port), tok] + (["--ttl", str(ttl)] if ttl else [])
        args += ["--iface-ip", iface_ip] if iface_ip else []
        result = in_ns(src, *args)
        time.sleep(1.0)
        after = counters()
        seen = [e for e in listener.events(since) if e.get("data") == tok] if listener else []
        drops = rose(before, after)
        if seen:
            observed = "delivered"
        elif drops:
            observed = "dropped"
        else:
            observed = f"lost:{result.get('result')}"
        self.check(name, "dropped", observed, f"send {result.get('result')}; listener saw {len(seen)}; {'; '.join(drops[:2])}")

    def with_route(self, container, gateway, dst="default"):
        ip_in(container, "route", "replace", dst, "via", gateway)

    def without_route(self, container, dst="default"):
        ip_in(container, "route", "del", dst)

    def capture(self, bpf, container=None):
        """tcpdump on every interface, on the host or in a container's namespace.

        stop() returns (interface, direction, line) for each packet seen.
        """
        path = os.path.join(self.work, f"cap-{secrets.token_hex(3)}.txt")
        out = open(path, "w")
        argv = ["tcpdump", "-i", "any", "-nn", "-l", "-y", "LINUX_SLL2"] + ([bpf] if bpf else [])
        if container is not None:
            argv = ns_argv(container) + argv
        proc = subprocess.Popen(argv, stdout=out, stderr=subprocess.DEVNULL)
        time.sleep(1.0)

        def stop():
            time.sleep(0.5)
            proc.send_signal(signal.SIGINT)
            proc.wait()
            out.close()
            with open(path, encoding="utf-8", errors="replace") as f:
                return [(p[1], p[2], line.strip()) for line in f if len(p := line.split()) > 2]

        return stop

    # The flows ------------------------------------------------------------------------

    def permitted(self, suffix=""):
        a = self.a
        self.tcp("recorder -> app port" + suffix, a.recorder, a.app_ip, APP_PORT, "open", self.l_app, a.id)
        self.tcp("verifier -> app port" + suffix, a.verifier, a.app_ip, APP_PORT, "open", self.l_app, a.id)
        self.tcp("verifier -> recorder tcp/4317" + suffix, a.verifier, a.recorder_ip, 4317, "open", self.l_rec, a.id)
        self.tcp("host as koi -> recorder tcp/4318" + suffix, ("user", "koi"), a.recorder_ip, 4318, "open", self.l_rec,
                 a.id)
        if not suffix:
            self.tcp("run B: verifier -> app port", self.b.verifier, self.b.app_ip, APP_PORT, "open", self.l_app_b,
                     self.b.id)

    def denied_inside(self):
        a = self.a
        rows = [
            ("app -> recorder tcp/4317", a.app, a.recorder_ip, 4317, self.l_rec),
            ("app -> recorder tcp/4318", a.app, a.recorder_ip, 4318, self.l_rec),
            ("app -> verifier tcp/9000", a.app, a.verifier_ip, 9000, self.l_ver),
            ("app -> verifier tcp/4317", a.app, a.verifier_ip, 4317, self.l_ver),
            ("recorder -> verifier tcp/9000", a.recorder, a.verifier_ip, 9000, self.l_ver),
            ("recorder -> verifier tcp/8080", a.recorder, a.verifier_ip, APP_PORT, self.l_ver),
            ("recorder -> app other port tcp/8081", a.recorder, a.app_ip, 8081, self.l_app),
            ("verifier -> recorder tcp/4318", a.verifier, a.recorder_ip, 4318, self.l_rec),
            ("verifier -> recorder tcp/9222", a.verifier, a.recorder_ip, 9222, self.l_rec),
            ("verifier -> recorder tcp/22", a.verifier, a.recorder_ip, 22, self.l_rec),
            ("verifier -> recorder tcp/80", a.verifier, a.recorder_ip, 80, self.l_rec),
            ("verifier -> recorder tcp/8080", a.verifier, a.recorder_ip, APP_PORT, self.l_rec),
            ("verifier -> app other port tcp/8081", a.verifier, a.app_ip, 8081, self.l_app),
            ("verifier -> app tcp/22", a.verifier, a.app_ip, 22, self.l_app),
        ]
        for name, src, ip, port, listener in rows:
            self.tcp(name, src, ip, port, "dropped", listener)
        self.udp("verifier -> app udp/9999", a.verifier, a.app_ip, 9999, self.l_app)
        self.udp("verifier -> recorder udp/9999", a.verifier, a.recorder_ip, 9999, self.l_rec)
        self.udp("app -> verifier udp/9999", a.app, a.verifier_ip, 9999, self.l_ver)
        self.udp("verifier -> multicast 224.0.0.251 udp/5353 (app joined)", a.verifier, "224.0.0.251", 5353, self.l_app,
                 ttl=1, iface_ip=a.verifier_ip)
        before = counters()
        res = in_ns(a.verifier, "_ping", "224.0.0.1", "--iface-ip", a.verifier_ip)
        drops = rose(before, counters())
        self.check("verifier -> multicast 224.0.0.1 icmp echo", "dropped",
                   "dropped" if res.get("result") != "answer" and drops else res.get("result", "?"), "; ".join(drops[:2]))
        before = counters()
        res = in_ns(a.verifier, "_ping", a.app_ip)
        drops = rose(before, counters())
        self.check("verifier -> app icmp echo", "dropped",
                   "dropped" if res.get("result") != "answer" and drops else res.get("result", "?"), "; ".join(drops[:2]))

    def denied_host(self):
        a = self.a
        host_ip = self.host_private_ip()
        for src in (a.verifier, a.recorder, a.app):
            role = "verifier" if src == a.verifier else "recorder" if src == a.recorder else "app"
            for port, listener in ((22, None), (18080, self.l_host), (7777, None), (2019, None)):
                self.tcp(f"{role} -> gateway {a.gateway} tcp/{port}", src, a.gateway, port, "dropped", listener)
        self.udp("verifier -> gateway udp/18081", a.verifier, a.gateway, 18081, self.l_host)
        # Off the /28: as created there is no route, so the probe adds one via
        # the gateway, to reach the firewall itself.
        res = in_ns(a.verifier, "_connect", host_ip, "22", "x")
        self.check("verifier has no route off its /28 (as koid creates it)", "unreachable", res.get("result", "?"),
                   f"connect {host_ip}:22 -> {res.get('result')}")
        self.with_route(a.verifier, a.gateway)
        self.tcp(f"verifier -> host private IP {host_ip} tcp/22 (test route)", a.verifier, host_ip, 22, "dropped", None)
        self.tcp(f"verifier -> host private IP {host_ip} tcp/18080 (test route)", a.verifier, host_ip, 18080,
                 "dropped", self.l_host)
        public = self.host_public_ip()
        if public:
            stop = self.capture(f"host {public}")
            self.tcp(f"verifier -> host public IP {public} tcp/22 hairpin (test route)", a.verifier, public, 22, "dropped", None)
            rows = stop()
            left = [r for r in rows if r[0] not in (a.bridge,) and not r[0].startswith("veth")]
            self.check("  hairpin: no packet to the public IP leaves the box", "none", "none" if not left else "left",
                       f"tcpdump saw {len(rows)} on kv/veth, {len(left)} elsewhere")
        self.without_route(a.verifier)

    def denied_dns(self):
        a = self.a
        name = f"koi-pkt-{secrets.token_hex(5)}.example.com"
        stop = self.capture("port 53")
        for proto in ("udp", "tcp"):
            before = counters()
            since = time.time()
            res = in_ns(a.verifier, "_dns", a.gateway, name, *(["--tcp"] if proto == "tcp" else []))
            time.sleep(0.3)
            drops = rose(before, counters())
            seen = self.l_dns[0].events(since)
            ok = res.get("result") in ("timeout", "unreachable") and not seen and drops
            self.check(f"verifier -> gateway {proto}/53 dns", "dropped", "dropped" if ok else res.get("result", "?"),
                       f"client {res.get('result')}; listener saw {len(seen)}; {'; '.join(drops[:1])}")
        # Docker's embedded resolver in the verifier's namespace forwards to
        # --dns, the gateway, where nothing may answer.
        before = counters()
        since = time.time()
        res = in_ns(a.verifier, "_dns", "127.0.0.11", name, "--timeout", "4")
        time.sleep(0.5)
        drops = rose(before, counters())
        seen = self.l_dns[0].events(since)
        self.check("verifier -> docker embedded resolver 127.0.0.11 (forward)",
                   "no-escape", "no-escape" if not seen else "escaped",
                   f"client {res.get('result')} rcode={res.get('rcode')}; gateway listener saw {len(seen)}; "
                   f"{'; '.join(drops[:1]) or 'no deny counted'}")
        self.with_route(a.verifier, a.gateway)
        for ip in ("1.1.1.1", "169.254.169.253", self.vpc_dns()):
            before = counters()
            res = in_ns(a.verifier, "_dns", ip, name)
            drops = rose(before, counters())
            self.check(f"verifier -> {ip} udp/53 dns (test route)", "dropped",
                       "dropped" if res.get("result") != "answer" and drops else res.get("result", "?"), "; ".join(drops[:1]))
        before = counters()
        res = in_ns(a.verifier, "_dns", "1.1.1.1", name, "--tcp")
        drops = rose(before, counters())
        self.check("verifier -> 1.1.1.1 tcp/53 dns (test route)", "dropped",
                   "dropped" if res.get("result") != "answer" and drops else res.get("result", "?"), "; ".join(drops[:1]))
        self.without_route(a.verifier)
        rows = stop()
        carrying = [r for r in rows if name in r[2]]
        escaped = [r for r in carrying if r[0] not in (a.bridge,) and not r[0].startswith("veth") and r[0] != "lo"]
        self.check("  dns: the probe name is never seen off the run bridge", "none", "none" if not escaped else "escaped",
                   f"{len(carrying)} packets carry it, on {sorted(set(r[0] for r in carrying))}; {len(escaped)} elsewhere")

    def denied_metadata_internet(self):
        a = self.a
        host_token = run(["curl", "-s", "-m", "3", "-X", "PUT", "-H", "X-aws-ec2-metadata-token-ttl-seconds: 60",
                          "http://169.254.169.254/latest/api/token"], check=False)
        live = host_token.returncode == 0 and host_token.stdout.strip() != ""
        self.report.note(f"control: the host itself {'gets' if live else 'does not get'} an IMDSv2 token")
        self.with_route(a.verifier, a.gateway)
        for name, ip, port, method, path in (
            ("verifier -> metadata 169.254.169.254 GET (test route)", "169.254.169.254", 80, "GET", "/latest/meta-data/"),
            ("verifier -> metadata IMDSv2 token PUT (test route)", "169.254.169.254", 80, "PUT", "/latest/api/token"),
            ("verifier -> 169.254.170.2 GET (test route)", "169.254.170.2", 80, "GET", "/"),
            ("verifier -> internet http://1.1.1.1/ (test route)", "1.1.1.1", 80, "GET", "/"),
        ):
            before = counters()
            res = in_ns(a.verifier, "_http", ip, str(port), method, path)
            drops = rose(before, counters())
            self.check(name, "dropped", "dropped" if res.get("result") != "answer" and drops else res.get("result", "?"),
                       f"client {res.get('result')}; {'; '.join(drops[:1])}")
        stop = self.capture("host 1.1.1.1 and tcp port 443")
        self.tcp("verifier -> internet 1.1.1.1 tcp/443 (test route)", a.verifier, "1.1.1.1", 443, "dropped", None)
        rows = stop()
        left = [r for r in rows if r[0] != a.bridge and not r[0].startswith("veth")]
        self.check("  internet: nothing to 1.1.1.1 leaves the box", "none", "none" if not left else "left",
                   f"tcpdump saw {len(rows)} on kv/veth, {len(left)} elsewhere")
        self.without_route(a.verifier)
        host = run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "5", "https://1.1.1.1/"], check=False)
        self.report.note(f"control: the host itself reaches https://1.1.1.1/ (status {host.stdout or host.returncode})")

    def host_side(self):
        a = self.a
        self.tcp("host as root -> recorder tcp/4318", None, a.recorder_ip, 4318, "dropped", self.l_rec)
        self.tcp("host as nobody -> recorder tcp/4318", ("user", "nobody"), a.recorder_ip, 4318, "dropped", self.l_rec)
        self.tcp("host as koi -> recorder tcp/4317", ("user", "koi"), a.recorder_ip, 4317, "dropped", self.l_rec)
        self.tcp("host as koi -> app port on the run network", ("user", "koi"), a.app_ip, APP_PORT, "dropped", self.l_app)
        self.tcp("host as koi -> verifier tcp/9000", ("user", "koi"), a.verifier_ip, 9000, "dropped", self.l_ver)

    def cross(self):
        a, b = self.a, self.b
        self.with_route(a.verifier, a.gateway)
        self.with_route(a.recorder, a.gateway)
        self.with_route(b.verifier, b.gateway)
        for name, src, ip, port, listener in (
            ("run A verifier -> run B app port", a.verifier, b.app_ip, APP_PORT, self.l_app_b),
            ("run A verifier -> run B recorder tcp/4317", a.verifier, b.recorder_ip, 4317, self.l_rec_b),
            ("run A verifier -> run B recorder tcp/4318", a.verifier, b.recorder_ip, 4318, self.l_rec_b),
            ("run A verifier -> run B verifier tcp/9000", a.verifier, b.verifier_ip, 9000, self.l_ver_b),
            ("run A recorder -> run B app port", a.recorder, b.app_ip, APP_PORT, self.l_app_b),
            ("run B verifier -> run A app port", b.verifier, a.app_ip, APP_PORT, self.l_app),
            ("run B verifier -> run A recorder tcp/4317", b.verifier, a.recorder_ip, 4317, self.l_rec),
        ):
            self.tcp(f"{name} (test route)", src, ip, port, "dropped", listener)
        # The app is on two networks; its preview address is not a way round.
        other_ip = self.preview_ip(self.other)
        app_preview_ip = self.preview_ip(a.app)
        self.tcp("verifier -> other preview's koi-previews address (test route)", a.verifier, other_ip, APP_PORT,
                 "dropped", self.l_other)
        self.tcp("verifier -> the run's app on its koi-previews address (test route)", a.verifier, app_preview_ip,
                 APP_PORT, "dropped", self.l_app)
        self.without_route(a.verifier)
        self.without_route(a.recorder)
        self.without_route(b.verifier)
        gw = self.preview_gateway()
        self.with_route(self.other, gw, str(self.pool))
        self.tcp("other preview -> run A app run-network address (test route)", self.other, a.app_ip, APP_PORT,
                 "dropped", self.l_app)
        self.tcp("other preview -> run A recorder tcp/4317 (test route)", self.other, a.recorder_ip, 4317, "dropped",
                 self.l_rec)
        self.tcp("other preview -> run A verifier tcp/9000 (test route)", self.other, a.verifier_ip, 9000, "dropped",
                 self.l_ver)
        self.without_route(self.other, str(self.pool))
        # The app keeps its own path out, from its preview address.
        if self.l_proxy is not None:
            since = time.time()
            res = in_ns(a.app, "_connect", gw, "3128", "proxy")
            seen = self.l_proxy.events(since)
            peers = sorted({e["peer"] for e in seen})
            ok = res.get("result") == "open" and peers == [app_preview_ip]
            self.check("app -> egress proxy port on koi-previews, from its preview address", "open",
                       "open" if ok else res.get("result", "?"),
                       f"listener saw peers {peers}, app preview address {app_preview_ip}")

    def ipv6(self):
        a = self.a
        for name in (a.app, a.verifier, a.recorder):
            done = run([*ns_argv(name), "sh", "-c", "cat /proc/sys/net/ipv6/conf/*/disable_ipv6 | sort -u"], check=False)
            self.report.note(f"{name}: disable_ipv6 values as created {done.stdout.split()}")
        with open(f"/proc/sys/net/ipv6/conf/{a.bridge}/disable_ipv6", encoding="ascii") as f:
            off = f.read().strip() == "1"
        self.check("run bridge has IPv6 off", "off", "off" if off else "on", f"/proc/sys/net/ipv6/conf/{a.bridge}/disable_ipv6")
        # Turn IPv6 on inside the app and the verifier, as a container that could
        # would, and pin the neighbour so the SYN itself is sent.
        # Fixed link-local addresses, with no address of the kernel's own, so
        # nothing is left tentative while duplicate address detection runs.
        addrs = {}
        for name, last in ((a.app, 2), (a.verifier, 4)):
            dev = self.dev_on(name, a.network)
            run([*ns_argv(name), "sysctl", "-q", "-w", f"net.ipv6.conf.{dev}.addr_gen_mode=1"], check=False)
            run([*ns_argv(name), "sysctl", "-q", "-w", f"net.ipv6.conf.{dev}.disable_ipv6=0"], check=False)
            mac = endpoint_of(name, a.network)[1]
            addrs[name] = (dev, mac, f"fe80::4b:{last}")
            ip_in(name, "-6", "addr", "add", f"fe80::4b:{last}/64", "dev", dev, "nodad")
        time.sleep(0.5)
        listener = Listener(self.work, "app-v6", a.app, tcp=[APP_PORT], v6=True)
        self.listeners.append(listener)
        vdev = addrs[a.verifier][0]
        app_dev, app_mac, app_ll = addrs[a.app]
        ip_in(a.verifier, "-6", "neigh", "replace", app_ll, "lladdr", app_mac, "dev", vdev, "nud", "permanent")
        before = counters()
        since = time.time()
        res = in_ns(a.verifier, "_connect", app_ll, str(APP_PORT), "v6", "--dev", vdev)
        drops = rose(before, counters())
        seen = listener.events(since)
        ok = res.get("result") in ("timeout", "unreachable") and not seen and any(d.startswith("ip6") for d in drops)
        self.check("verifier -> app port over IPv6 link-local", "dropped", "dropped" if ok else res.get("result", "?"),
                   f"client {res.get('result')}; listener saw {len(seen)}; {'; '.join(drops[:2])}")
        before = counters()
        run([*ns_argv(a.verifier), "ping", "-6", "-c", "1", "-W", "1", f"ff02::1%{vdev}"], check=False)
        drops = rose(before, counters())
        self.check("verifier -> ff02::1 icmpv6", "dropped", "dropped" if any(d.startswith("ip6") for d in drops) else "passed",
                   "; ".join(drops[:2]) or "no ip6 deny counted (ping may be missing)")
        for name in (a.app, a.verifier):
            run([*ns_argv(name), "sysctl", "-q", "-w", f"net.ipv6.conf.{addrs[name][0]}.disable_ipv6=1"], check=False)

    def dev_on(self, name, network):
        mac = endpoint_of(name, network)[1]
        links = json.loads(ip_in(name, "-j", "link", "show").stdout)
        return next(link["ifname"] for link in links if link.get("address") == mac)

    def capabilities(self):
        a = self.a
        for role, name in (("verifier", a.verifier), ("recorder", a.recorder), ("app", a.app)):
            res = in_container(name, "_rawcheck")
            denied = all(res.get(k) == "eperm" for k in ("packet", "raw_tcp", "raw_ip"))
            self.check(f"{role} (its own process) cannot open raw or packet sockets", "eperm",
                       "eperm" if denied else "allowed", json.dumps(res))

    def forge(self, name, src_ip, src_mac, dst_ip, dst_mac, port, target, listener, udp=False, encap="",
              expect="blocked", known=False):
        """Frames sent by the attacker container; whether they reached the target's interface, and any answer."""
        # A filter on ports does not see through a VLAN tag or PPPoE, so those probes capture everything.
        stop = self.capture("" if encap else f"dst port {port}", container=target)
        before = counters()
        since = time.time()
        args = ["_forge", "--src-ip", src_ip, "--src-mac", src_mac, "--dst-ip", dst_ip, "--dst-mac", dst_mac,
                "--dport", str(port)] + (["--udp", "--token", "forged-udp"] if udp else []) + (["--encap", encap] if encap else [])
        res = in_container(self.attacker, *args)
        time.sleep(0.5)
        drops = rose(before, counters())
        rows = stop()
        arrived = [r for r in rows if r[1] == "In" and f"{src_ip}." in r[2] and f"> {dst_ip}.{port}" in r[2]]
        seen = [e for e in listener.events(since) if e.get("port") == port] if listener else []
        if res.get("synack"):
            observed = "answered"
        elif arrived or seen:
            observed = "reached"
        else:
            observed = "blocked"
        how = (f"sent {res.get('sent')}; reached target {len(arrived)}; synack={res.get('synack')}; "
               f"listener saw {len(seen)}; {'; '.join(drops[:2]) or 'no deny counted'}")
        if res.get("stderr"):
            how += f"; {res['stderr']}"
        self.check(name, expect, observed, how, known)
        self.relearn()
        return observed

    def relearn(self):
        """Each running endpoint sends a frame, so the bridge learns its MAC on its own port again.

        A forged frame teaches the bridge that the forged MAC is on the
        attacker's port, and the bridge then sends that endpoint's traffic
        there. Without this, a later probe would test the bridge's forwarding
        table and not the firewall.
        """
        a = self.a
        self.relearn_neighbours()
        for name in (a.app, a.recorder, a.verifier):
            if docker("inspect", "--format", "{{.State.Running}}", name, check=False).stdout.strip() == "true":
                in_ns(name, "_ping", a.gateway, "--timeout", "0.2")

    def spoofing(self):
        a = self.a
        rec_mac, ver_mac = helper_mac(a.recorder_ip), helper_mac(a.verifier_ip)
        self.forge("attacker forging verifier IP+MAC -> recorder tcp/4317", a.verifier_ip, ver_mac, a.recorder_ip,
                   rec_mac, 4317, a.recorder, self.l_rec)
        self.forge("attacker forging verifier IP+MAC -> app port", a.verifier_ip, ver_mac, a.app_ip, a.app_mac,
                   APP_PORT, a.app, self.l_app)
        self.forge("attacker forging recorder IP+MAC -> app port", a.recorder_ip, rec_mac, a.app_ip, a.app_mac,
                   APP_PORT, a.app, self.l_app)
        with open(f"/sys/class/net/{a.bridge}/address", encoding="ascii") as f:
            bridge_mac = f.read().strip()
        self.forge("attacker forging gateway IP+MAC -> recorder tcp/4318", a.gateway, bridge_mac, a.recorder_ip,
                   rec_mac, 4318, a.recorder, self.l_rec)
        self.forge("attacker own address -> recorder tcp/4318", self.attacker_ip, self.attacker_mac, a.recorder_ip,
                   rec_mac, 4318, a.recorder, self.l_rec)
        self.forge("attacker own address -> verifier udp/9999", self.attacker_ip, self.attacker_mac, a.verifier_ip,
                   ver_mac, 9999, a.verifier, self.l_ver, udp=True)
        # 802.1Q priority-tagged frames (VLAN id 0). The receiving kernel strips
        # such a tag and takes the packet as untagged. br_netfilter hands a
        # frame under one tag to iptables only with
        # bridge-nf-filter-vlan-tagged=1, and one under two tags never; the
        # helper's layer 2 allowlist drops both before iptables is asked.
        self.report.note(f"bridge-nf-filter-vlan-tagged={read_sysctl('net.bridge.bridge-nf-filter-vlan-tagged')}")
        self.forge("attacker vlan-0 tagged udp -> recorder udp/9999", self.attacker_ip, self.attacker_mac,
                   a.recorder_ip, rec_mac, 9999, a.recorder, self.l_rec, udp=True, encap="vlan0")
        self.forge("attacker vlan-0 tagged SYN -> recorder tcp/4318", self.attacker_ip, self.attacker_mac,
                   a.recorder_ip, rec_mac, 4318, a.recorder, self.l_rec, encap="vlan0")
        self.forge("attacker vlan-0 tagged SYN forging verifier -> recorder tcp/4318", a.verifier_ip, ver_mac,
                   a.recorder_ip, rec_mac, 4318, a.recorder, self.l_rec, encap="vlan0")
        self.forge("attacker double vlan-0 tagged udp -> recorder udp/9999", self.attacker_ip, self.attacker_mac,
                   a.recorder_ip, rec_mac, 9999, a.recorder, self.l_rec, udp=True, encap="qinq")
        self.forge("attacker 802.1ad+802.1Q tagged udp -> recorder udp/9999", self.attacker_ip, self.attacker_mac,
                   a.recorder_ip, rec_mac, 9999, a.recorder, self.l_rec, udp=True, encap="adq")
        self.forge("attacker double vlan-0 tagged SYN forging verifier -> recorder tcp/4317", a.verifier_ip, ver_mac,
                   a.recorder_ip, rec_mac, 4317, a.recorder, self.l_rec, encap="qinq")
        # A PPPoE session frame: the receiving kernel has no session to take
        # it into, so even unfiltered it reaches no socket; the allowlist
        # keeps it off the target's port as well.
        self.report.note(f"bridge-nf-filter-pppoe-tagged={read_sysctl('net.bridge.bridge-nf-filter-pppoe-tagged')}")
        self.forge("attacker pppoe udp -> recorder udp/9999", self.attacker_ip, self.attacker_mac,
                   a.recorder_ip, rec_mac, 9999, a.recorder, self.l_rec, udp=True, encap="pppoe")

    def unbound_window(self):
        """Before a container runs, its permits match its address and MAC only (docs/verify.md says so)."""
        a = self.a
        self.report.note("the verifiers are created but not started: their permits have no bridge port yet")
        self.forge("attacker forging verifier IP+MAC -> recorder tcp/4317, verifier not started", a.verifier_ip,
                   helper_mac(a.verifier_ip), a.recorder_ip, helper_mac(a.recorder_ip), 4317, a.recorder, self.l_rec,
                   known=True)

    def interception(self):
        """A permitted flow's packets go to whichever port the bridge sends the destination MAC to.

        Two ways to have them sent to the attacker: frames from the
        destination's MAC, so the bridge learns it on the attacker's port
        (the pins stop that), and ARP that tells the sender the destination's
        address is at the attacker's MAC (--physdev-out stops that between
        containers, the host's permanent neighbour for the host).
        """
        a = self.a
        rec_mac, ver_mac = helper_mac(a.recorder_ip), helper_mac(a.verifier_ip)
        with open(f"/sys/class/net/{a.bridge}/address", encoding="ascii") as f:
            bridge_mac = f.read().strip()
        verifier_hold = [*ns_argv(a.verifier), sys.executable, "-I", SELF, "_hold", a.recorder_ip, "4317"]
        host_hold = ["runuser", "-u", "koi", "--", sys.executable, "-I", self.probe, "_hold", a.recorder_ip, "4318"]
        poison = ["--poison", rec_mac, "--poison-ip", a.recorder_ip]
        self.intercept("attacker poisoning the bridge with the recorder's MAC reads verifier -> recorder:4317 data",
                       verifier_hold, poison)
        self.intercept("attacker poisoning the bridge with the recorder's MAC reads host as koi -> recorder:4318 data",
                       host_hold, poison)
        self.intercept("attacker ARP-claiming the recorder's address to the verifier reads verifier -> recorder:4317",
                       verifier_hold, ["--victim-mac", ver_mac, "--victim-ip", a.verifier_ip, "--claim", a.recorder_ip])
        self.intercept("attacker ARP-claiming the verifier's address to the recorder reads the recorder's replies",
                       verifier_hold, ["--victim-mac", rec_mac, "--victim-ip", a.recorder_ip, "--claim", a.verifier_ip])
        self.intercept("attacker ARP-claiming the recorder's address to the host reads host as koi -> recorder:4318",
                       host_hold, ["--victim-mac", bridge_mac, "--victim-ip", a.gateway, "--claim", a.recorder_ip])

    def intercept(self, name, hold_argv, attack):
        """A held connection sends eight markers while the attacker runs `attack`; whether the attacker saw one."""
        marker = f"koi-secret-{secrets.token_hex(4)}"
        hold = subprocess.Popen(hold_argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        first = json.loads(hold.stdout.readline())
        if first.get("result") != "open":
            hold.kill()
            self.check(name, "not-read", "not-run", f"could not connect: {first}")
            return
        with open(SELF, encoding="utf-8") as f:
            source = f.read()
        att = subprocess.Popen(["docker", "exec", "-i", self.attacker, "python3", "-I", "-", "_intercept", *attack,
                                "--marker", marker, "--seconds", "6"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        att.stdin.write(source)
        att.stdin.close()
        att.stdout.readline()
        time.sleep(0.5)
        results = []
        for i in range(8):
            try:
                hold.stdin.write(f"{marker}-{i}\n")
                hold.stdin.flush()
                results.append(json.loads(hold.stdout.readline() or "{}"))
            except (BrokenPipeError, ValueError):
                break
            time.sleep(0.3)
        out = att.stdout.read()
        att.wait()
        try:
            hold.stdin.close()
        except BrokenPipeError:
            pass
        hold.kill()
        hold.wait()
        got = json.loads(out.strip().splitlines()[-1])
        self.check(name, "not-read", "read" if got.get("intercepted") else "not-read",
                   f"connection {first.get('result')}; frame {got.get('frame')}; "
                   f"sender got {sum(r.get('result') == 'echo' for r in results)}/8 echoes")
        self.relearn()

    def relearn_neighbours(self):
        """Forgets every neighbour a spoofed ARP may have left: in each container, and on the host for run A's bridge.

        `ip neigh flush` leaves permanent entries, the helper's pin among them.
        """
        a = self.a
        for name in (a.app, a.recorder, a.verifier):
            if docker("inspect", "--format", "{{.State.Running}}", name, check=False).stdout.strip() == "true":
                ip_in(name, "neigh", "flush", "all")
        run(["ip", "neigh", "flush", "dev", a.bridge], check=False)

    def pins(self):
        """Each running endpoint's MAC is a static sticky entry on its own port, and the recorder's address a permanent neighbour."""
        a = self.a
        attest = json.loads(helper("attest").stdout)
        ports = (attest.get("ports") or {}).get(a.id) or {}
        entries = json.loads(run(["bridge", "-j", "fdb", "show", "br", a.bridge]).stdout or "[]")
        bad = []
        for role, mac in (("app", a.app_mac), ("recorder", helper_mac(a.recorder_ip)), ("verifier", helper_mac(a.verifier_ip))):
            mine = [e for e in entries if e.get("mac") == mac]
            if not mine or not all(e.get("ifname") == ports.get(role) and e.get("state") == "static"
                                   and "sticky" in (e.get("flags") or []) for e in mine):
                bad.append(f"{role} {mac}: {mine}")
        neigh = json.loads(run(["ip", "-4", "-j", "neigh", "show", "dev", a.bridge]).stdout or "[]")
        held = [e for e in neigh if e.get("dst") == a.recorder_ip]
        if not any(e.get("lladdr") == helper_mac(a.recorder_ip) and "PERMANENT" in (e.get("state") or []) for e in held):
            bad.append(f"neighbour {a.recorder_ip}: {held}")
        bridge = attest.get("bridge") or {}
        ok = not bad and bridge.get("guard") is True and bridge.get("pins") is True
        self.check("run A: endpoint MACs pinned to their ports, recorder a permanent neighbour, attested", "pinned",
                   "pinned" if ok else "missing", f"{'; '.join(bad)[:300] or 'fdb and neighbour as wanted'}; attest bridge={bridge}")

    def layer2(self):
        """The helper's provision left the allowlist in front of ebtables FORWARD and the VLAN sysctl at 1."""
        listing = run(["ebtables", "-t", "filter", "-L"]).stdout
        rules = re.findall(r"^(--logical-in kv\+ -j KOI-VERIFY-L2|-p \S+ -j RETURN|-j DROP)$", listing, re.M)
        vlan = read_sysctl("net.bridge.bridge-nf-filter-vlan-tagged")
        ok = rules[:1] == ["--logical-in kv+ -j KOI-VERIFY-L2"] and len(rules) >= 4 and vlan == "1"
        self.check("layer 2 allowlist in ebtables FORWARD, bridge-nf-filter-vlan-tagged=1", "ok", "ok" if ok else "missing",
                   f"ebtables {rules}; vlan-tagged={vlan}")

    def teardown(self):
        """koid's order: revoke, then take the app off the network, remove the helpers and the network."""
        a = self.a
        hold = subprocess.Popen([*ns_argv(a.verifier), sys.executable, "-I", SELF, "_hold", a.app_ip, str(APP_PORT),
                                 "--timeout", "3"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        first = json.loads(hold.stdout.readline())
        hold.stdin.write("before-revoke\n")
        hold.stdin.flush()
        before_revoke = json.loads(hold.stdout.readline())
        self.check("teardown: established verifier -> app passes before revoke", "echo", before_revoke.get("result", "?"),
                   f"open {first.get('result')}")
        entries = run(["conntrack", "-L", "-s", str(a.subnet)], check=False).stdout.count("\n")
        done = helper("revoke", a.id)
        self.check("teardown: revoke through sudo as koi", "ok", "ok" if done.returncode == 0 else f"exit{done.returncode}",
                   (done.stdout or done.stderr).strip()[-200:])
        after_entries = run(["conntrack", "-L", "-s", str(a.subnet)], check=False).stdout.count("\n")
        self.check("teardown: conntrack entries of the subnet flushed", "flushed",
                   "flushed" if after_entries == 0 else f"{after_entries}-left", f"{entries} before, {after_entries} after")
        before = counters()
        since = time.time()
        hold.stdin.write("after-revoke\n")
        hold.stdin.flush()
        after_revoke = json.loads(hold.stdout.readline())
        hold.stdin.close()
        hold.wait()
        drops = rose(before, counters())
        seen = [e for e in self.l_app.events(since) if e.get("data") == "after-revoke"]
        ok = after_revoke.get("result") != "echo" and not seen
        self.check("teardown: the established connection stops after revoke", "stopped", "stopped" if ok else "passed",
                   f"client {after_revoke.get('result')}; app saw {len(seen)}; {'; '.join(drops[:2])}")
        self.tcp("teardown: verifier -> app port after revoke", a.verifier, a.app_ip, APP_PORT, "dropped", self.l_app)
        self.tcp("teardown: recorder -> app port after revoke", a.recorder, a.app_ip, APP_PORT, "dropped", self.l_app)
        self.tcp("teardown: host as koi -> recorder tcp/4318 after revoke", ("user", "koi"), a.recorder_ip, 4318,
                 "dropped", self.l_rec)
        left = [line for line in run(["iptables-save"]).stdout.splitlines() if f"koi-run={a.id}" in line]
        self.check("teardown: no rule of the run is left", "none", "none" if not left else f"{len(left)}-left", "iptables-save")
        static = [e for e in json.loads(run(["bridge", "-j", "fdb", "show", "br", a.bridge]).stdout or "[]")
                  if e.get("state") == "static"]
        permanent = [e for e in json.loads(run(["ip", "-4", "-j", "neigh", "show", "dev", a.bridge]).stdout or "[]")
                     if "PERMANENT" in (e.get("state") or [])]
        self.check("teardown: the run's MAC pins and the recorder's neighbour are gone", "none",
                   "none" if not static and not permanent else f"{len(static)}+{len(permanent)}-left",
                   f"static {[(e.get('mac'), e.get('ifname')) for e in static]}; permanent {[e.get('dst') for e in permanent]}")
        docker("network", "disconnect", a.network, a.app, check=False)
        docker("rm", "--force", "--volumes", a.recorder, a.verifier, self.attacker, check=False)
        rm = docker("network", "rm", a.network, check=False)
        self.check("teardown: run network removed", "ok", "ok" if rm.returncode == 0 else "failed", rm.stderr.strip()[-200:])

    def refusals(self):
        b = self.b

        def refused(name, text, want):
            before = run(["iptables-save"]).stdout
            states = sorted(os.listdir(STATE_DIR))
            done = helper("apply", stdin=text)
            after = run(["iptables-save"]).stdout
            def bare(text):
                return re.sub(r"\[\d+:\d+\]|^#.*$", "", text, flags=re.M)

            unchanged = bare(before) == bare(after)
            unchanged = unchanged and states == sorted(os.listdir(STATE_DIR))
            msg = done.stderr.strip()
            ok = done.returncode == 2 and want in msg and unchanged
            self.check(name, "refused", "refused" if ok else f"exit{done.returncode}",
                       f"{msg[-160:]}; rules and state {'unchanged' if unchanged else 'CHANGED'}")

        outside = ipaddress.ip_network(f"{self.pool.broadcast_address + 1}/28", strict=False)
        hosts = list(outside.hosts())
        d = json.loads(b.descriptor())
        d["subnet"] = str(outside)
        for e, h in zip(d["endpoints"], hosts[1:4], strict=True):
            e["ip"] = str(h)
        refused("helper refuses a subnet outside the pool", json.dumps(d), "outside the reserved pool")
        d = json.loads(b.descriptor())
        d["runId"] = f"pkt{secrets.token_hex(10)}"
        refused("helper refuses a subnet that overlaps another run", json.dumps(d), "overlaps run")
        d = json.loads(b.descriptor())
        d["endpoints"][1]["mac"] = "02:4b:00:00:00:99"
        refused("helper refuses an endpoint whose MAC is not Docker's", json.dumps(d), "has mac")
        d = json.loads(b.descriptor())
        d["endpoints"][0]["container"] = b.recorder
        refused("helper refuses an app that is not a preview", json.dumps(d), "is not a preview")

    # Facts -----------------------------------------------------------------------------

    def host_private_ip(self):
        out = run(["ip", "-j", "route", "get", "1.1.1.1"]).stdout
        return json.loads(out)[0]["prefsrc"]

    def host_public_ip(self):
        tok = run(["curl", "-s", "-m", "3", "-X", "PUT", "-H", "X-aws-ec2-metadata-token-ttl-seconds: 60",
                   "http://169.254.169.254/latest/api/token"], check=False).stdout.strip()
        if not tok:
            return None
        ip = run(["curl", "-s", "-m", "3", "-H", f"X-aws-ec2-metadata-token: {tok}",
                  "http://169.254.169.254/latest/meta-data/public-ipv4"], check=False).stdout.strip()
        return ip if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) else None

    def vpc_dns(self):
        """The VPC resolver: the host network's base address plus two, as on EC2."""
        return str(ipaddress.ip_interface(self.host_cidr()).network.network_address + 2)

    def host_cidr(self):
        for link in json.loads(run(["ip", "-j", "-4", "addr", "show", "scope", "global"]).stdout):
            if link["ifname"].startswith(("kv", "koi-", "docker", "br-", "veth")):
                continue
            for info in link.get("addr_info", []):
                return f"{info['local']}/{info['prefixlen']}"
        return "127.0.0.1/8"

    def show_rules(self):
        for line in run(["iptables", "-S"]).stdout.splitlines():
            if "KOI-VERIFY" in line or "kv" in line:
                print("      " + line)

    def main(self):
        self.prerequisites()
        self.provision_twice()
        cleanup()
        try:
            self.setup()
            self.listeners_up()
            self.unbound_window()
            self.start_verifiers()
            self.verifier_listeners_up()
            if self.verbose:
                self.show_rules()
            self.layer2()
            self.pins()
            self.capabilities()
            self.permitted()
            self.denied_inside()
            self.host_side()
            self.denied_host()
            self.denied_dns()
            self.denied_metadata_internet()
            self.cross()
            self.ipv6()
            self.spoofing()
            self.interception()
            self.permitted(" (again, after spoofing)")
            self.refusals()
            self.teardown()
        except Abort as err:
            self.report.add(f"aborted: {err}"[:58], "ran", "aborted", False, str(err))
        finally:
            for listener in self.listeners:
                listener.stop()
            if not self.keep:
                cleanup([r.id for r in self.runs])
                shutil.rmtree(self.work, ignore_errors=True)
        print(f"{len(self.report.lines)} checks, {self.report.failed} failed, {self.report.gaps} known gaps seen")
        return 1 if self.report.failed else 0


def main(argv):
    if argv and argv[0].startswith("_"):
        probe_main(argv)
        return 0
    p = argparse.ArgumentParser(description="Packet tests for koi's verification run network. Run as root.")
    p.add_argument("--keep", action="store_true", help="leave the networks and containers for inspection")
    p.add_argument("--verbose", action="store_true", help="print the run's rules after apply")
    p.add_argument("--cleanup", action="store_true", help="only remove what an earlier test left")
    args = p.parse_args(argv)
    if args.cleanup:
        cleanup()
        return 0
    try:
        return PacketTest(args.keep, args.verbose).main()
    except Abort as err:
        print(f"FAIL  {err}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
