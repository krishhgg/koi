#!/usr/bin/env python3
"""koi-verify-net: the firewall permits of one verification run.

koid runs as koi and cannot change iptables. For a verification run it needs
a handful of permits on the run's private bridge, so provisioning installs
this file at /usr/local/libexec/koi-verify-net, owned by root, with a sudoers
rule that lets koi run exactly this path. It is the only way koid changes
the firewall, and it takes four commands:

  provision      creates the KOI-VERIFY chains with their default denies and
                 the jumps that reach them, or brings an older layout up to
                 date. Run as root by provisioning (host/cloud-init.sh) and
                 by the helper's installer, never by koid. It keeps every
                 run's permits, and a chain it rebuilds is reached before the
                 old one goes, so kv+ traffic is confined at every instant;
  apply          reads one JSON descriptor on stdin (docs/verify.md, "Run
                 network") and installs that run's permits as one
                 generation of rules;
  revoke RUN     removes that generation from every KOI-VERIFY chain and
                 the run's connection tracking entries;
  attest         prints a JSON summary of the chains, of the path that
                 reaches them and of the bridge filtering sysctls, for
                 koid's host check.

Every field of the descriptor is checked against a fixed shape before any
command runs. The permits are the exact connections the design allows
(recorder and verifier to the app port, verifier to the recorder's port 4317,
the host to the recorder's port 4318, and their replies), bound to the run's
bridge, each endpoint's address and MAC, and its bridge port when the
container runs. Nothing a caller writes in the descriptor becomes a chain
name, a port of its choosing or shell text. Standard library only.

Rules are never compared as text. `iptables -S` prints a rule in its own
order (addresses first, then interfaces, protocol, matches and target), with
a /32 on a bare address, MACs in upper case and quotes around a comment, so
every listing is parsed into a canonical form first and compared as that.
Each option takes a fixed number of values, so a value is read by position,
never by what it looks like, and a rule with an option the parser does not
know is reported, never passed as harmless.

apply and revoke first finish or discard a chain swap an interrupted
provision left, so the permits they install or remove are in the chains
every command reads.

A run's state file under /run/koi-verify is written before its first rule
and removed after its last connection tracking entry, so the subnet to flush
is on record whenever a rule of the run can exist.
"""

import fcntl
import ipaddress
import json
import os
import pwd
import re
import shlex
import subprocess
import sys

# Bumped when the rules this file installs change shape. koid refuses to
# verify on a host whose helper reports another version.
POLICY_VERSION = 1

ENV_FILE = "/etc/koi/verify/env"
STATE_DIR = "/run/koi-verify"
LOCK_FILE = "/run/koi-verify.lock"

# The chains provision creates. KOI-VERIFY is reached from DOCKER-USER, so it
# sees bridged traffic before Docker's own rules; the other two are reached
# from INPUT and OUTPUT for kv+ interfaces.
CHAIN_FORWARD = "KOI-VERIFY"
CHAIN_INPUT = "KOI-VERIFY-IN"
CHAIN_OUTPUT = "KOI-VERIFY-OUT"
# Every chain of the helper's, permanent or staged for a swap, has this prefix.
CHAIN_PREFIX = "KOI-VERIFY"


def _rules(*lines):
    return [line.split() for line in lines]


# The defaults at the end of each chain, in order. A run's permits go above
# them; attest checks that each chain ends with them and holds nothing else.
BASE_FORWARD = _rules(
    "-i kv+ -m conntrack --ctstate INVALID -j DROP",
    "-o kv+ -m conntrack --ctstate INVALID -j DROP",
    "-i kv+ -p udp -j DROP",
    "-i kv+ -d 224.0.0.0/4 -j DROP",
    "-i kv+ -d 169.254.0.0/16 -j DROP",
    "-i kv+ -p tcp -m tcp --dport 53 -j DROP",
    "-i kv+ -j DROP",
    "-o kv+ -j DROP",
)
BASE_INPUT = _rules(
    "-m conntrack --ctstate INVALID -j DROP",
    "-p udp -j DROP",
    "-j DROP",
)
BASE_OUTPUT = _rules(
    "-m conntrack --ctstate INVALID -j DROP",
    "-p udp -j DROP",
    "-j DROP",
)

# Each chain: where it is reached from and with what match on that jump, its
# defaults, and which interface options say whether a rule of the parent can
# see kv+ traffic at all (forwarded traffic has an in and an out interface;
# input only an in interface; output only an out interface).
CHAINS = [
    {"chain": CHAIN_FORWARD, "parent": "DOCKER-USER", "match": [], "base": BASE_FORWARD, "flags": ("-i", "-o")},
    {"chain": CHAIN_INPUT, "parent": "INPUT", "match": ["-i", "kv+"], "base": BASE_INPUT, "flags": ("-i",)},
    {"chain": CHAIN_OUTPUT, "parent": "OUTPUT", "match": ["-o", "kv+"], "base": BASE_OUTPUT, "flags": ("-o",)},
]
# IPv6 is denied outright on every kv+ interface; the run networks are IPv4
# only and the bridge's own IPv6 is switched off on apply.
BASE_IPV6 = [
    ("INPUT", ["-i", "kv+", "-j", "DROP"], ("-i",)),
    ("FORWARD", ["-i", "kv+", "-j", "DROP"], ("-i", "-o")),
    ("FORWARD", ["-o", "kv+", "-j", "DROP"], ("-i", "-o")),
    ("OUTPUT", ["-o", "kv+", "-j", "DROP"], ("-o",)),
]

RECORDER_CONTROL_PORT = 4318
RECORDER_PLAYWRIGHT_PORT = 4317
# The host user whose connections to the recorder's control port pass.
KOI_USER = "koi"

RUN_ID = re.compile(r"^[a-z0-9]{16,40}$")
BRIDGE = re.compile(r"^kv[0-9a-f]{12}$")
MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
CONTAINER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
IFNAME = re.compile(r"^[a-zA-Z0-9_.-]{1,15}$")
ROLES = ("app", "recorder", "verifier")
# Host numbers inside the /28: the gateway is .1.
OFFSETS = {"app": 2, "recorder": 3, "verifier": 4}
MAX_DESCRIPTOR_BYTES = 64 * 1024

PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


class Refused(Exception):
    """Bad input, or a host that is not as provisioning leaves it. Exit 2."""


class Failed(Exception):
    """A command failed part way. Exit 1. Carries the command's exit code and stderr when it ran."""

    def __init__(self, message, returncode=None, stderr=""):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


# --- Descriptor ----------------------------------------------------------------


def read_pool(path=None):
    """The reserved pool from the KOI_VERIFY_POOL line of the env file, or None."""
    path = ENV_FILE if path is None else path
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return None
    for line in lines:
        key, sep, value = line.strip().partition("=")
        if sep and key == "KOI_VERIFY_POOL":
            return parse_pool(value.strip().strip("'\""))
    return None


def parse_pool(text):
    try:
        pool = ipaddress.ip_network(text, strict=True)
    except ValueError as err:
        raise Refused(f"KOI_VERIFY_POOL {text!r} is not a network: {err}") from None
    if pool.version != 4:
        raise Refused("KOI_VERIFY_POOL must be an IPv4 network")
    if not 16 <= pool.prefixlen <= 28:
        raise Refused("KOI_VERIFY_POOL must be between a /16 and a /28")
    return pool


def parse_descriptor(text, pool):
    """The descriptor as a dict with parsed fields, or Refused. Every key is checked."""
    if pool is None:
        raise Refused(f"no KOI_VERIFY_POOL in {ENV_FILE}; the host is not provisioned for verification")
    if len(text) > MAX_DESCRIPTOR_BYTES:
        raise Refused("the descriptor is too large")
    try:
        data = json.loads(text)
    except ValueError:
        raise Refused("the descriptor is not JSON") from None
    if not isinstance(data, dict):
        raise Refused("the descriptor is not an object")
    want = {"version", "runId", "bridge", "subnet", "appPort", "endpoints"}
    if set(data) != want:
        extra = sorted(set(data) - want)
        missing = sorted(want - set(data))
        raise Refused(f"descriptor keys: missing {missing}, unknown {extra}")
    if data["version"] != 1:
        raise Refused("descriptor version must be 1")
    run_id = data["runId"]
    if not isinstance(run_id, str) or not RUN_ID.match(run_id):
        raise Refused("runId must be 16 to 40 lowercase letters and digits")
    bridge = data["bridge"]
    if not isinstance(bridge, str) or not BRIDGE.match(bridge):
        raise Refused("bridge must be kv and 12 hex digits")
    if not isinstance(data["subnet"], str):
        raise Refused("subnet must be a string")
    try:
        subnet = ipaddress.ip_network(data["subnet"], strict=True)
    except ValueError as err:
        raise Refused(f"subnet: {err}") from None
    if subnet.version != 4 or subnet.prefixlen != 28:
        raise Refused("subnet must be an IPv4 /28")
    if not subnet.subnet_of(pool):
        raise Refused(f"subnet {subnet} is outside the reserved pool {pool}")
    port = data["appPort"]
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise Refused("appPort must be an integer from 1 to 65535")
    endpoints = data["endpoints"]
    if not isinstance(endpoints, list) or len(endpoints) != 3:
        raise Refused("endpoints must list exactly three endpoints")
    parsed = {}
    macs = set()
    for entry in endpoints:
        if not isinstance(entry, dict) or set(entry) != {"role", "container", "ip", "mac"}:
            raise Refused("each endpoint has exactly role, container, ip and mac")
        role = entry["role"]
        if role not in ROLES:
            raise Refused(f"endpoint role {role!r} is not one of {', '.join(ROLES)}")
        if role in parsed:
            raise Refused(f"endpoint role {role} appears twice")
        container = entry["container"]
        if not isinstance(container, str) or not CONTAINER.match(container):
            raise Refused(f"{role}: container is not a Docker name")
        if not isinstance(entry["ip"], str):
            raise Refused(f"{role}: ip must be a string")
        try:
            ip = ipaddress.ip_address(entry["ip"])
        except ValueError:
            raise Refused(f"{role}: ip {entry['ip']!r} is not an address") from None
        if ip != subnet[OFFSETS[role]]:
            raise Refused(f"{role}: ip must be {subnet[OFFSETS[role]]} in {subnet}, not {ip}")
        mac = entry["mac"]
        if not isinstance(mac, str) or not MAC.match(mac):
            raise Refused(f"{role}: mac must be six lowercase hex pairs separated by colons")
        first = int(mac[:2], 16)
        if first & 0x01 or not first & 0x02:
            raise Refused(f"{role}: mac must be a locally administered unicast address")
        if mac in macs:
            raise Refused("two endpoints share a mac")
        macs.add(mac)
        parsed[role] = {"container": container, "ip": str(ip), "mac": mac}
    if set(parsed) != set(ROLES):
        raise Refused("endpoints must cover app, recorder and verifier")
    return {
        "runId": run_id,
        "bridge": bridge,
        "subnet": str(subnet),
        "gateway": str(subnet[1]),
        "appPort": port,
        "endpoints": parsed,
    }


def network_name(run_id):
    return f"koi-v-{run_id}"


# --- Rules as iptables prints them --------------------------------------------------

# Long spellings iptables accepts, folded onto the short ones it prints.
ALIASES = {
    "--src": "-s",
    "--source": "-s",
    "--dst": "-d",
    "--destination": "-d",
    "--in-interface": "-i",
    "--out-interface": "-o",
    "--protocol": "-p",
    "--jump": "-j",
    "--goto": "-g",
    "--match": "-m",
    "--fragment": "-f",
    "--set-counters": "-c",
    "--destination-port": "--dport",
    "--source-port": "--sport",
    "--destination-ports": "--dports",
    "--source-ports": "--sports",
}
PORT_OPTIONS = ("--dport", "--sport")
COMMENT_PREFIX = "koi-run="

# Every option the parser knows, with how many values follow it. Each value
# is taken by position, whatever it looks like: a comment of "!" or "-j" is
# the comment, never a negation or a target. iptables prints a value bare
# unless it holds a character outside [A-Za-z0-9_-], so "-j" as a comment
# comes out unquoted and only the count tells it apart from the option. A
# rule with an option not listed here is left unparsed, and attest treats an
# unparsed rule as one that could let traffic past, never as harmless.
OPTION_ARITY = {
    # The rule itself.
    "-s": 1, "-d": 1, "-i": 1, "-o": 1, "-p": 1, "-m": 1, "-j": 1, "-g": 1, "-f": 0, "-c": 2,
    # tcp, udp, icmp, icmp6, sctp, dccp, mh, esp, ah.
    "--sport": 1, "--dport": 1, "--tcp-flags": 2, "--syn": 0, "--tcp-option": 1,
    "--icmp-type": 1, "--icmpv6-type": 1, "--chunk-types": 2, "--dccp-types": 1, "--dccp-option": 1,
    "--mh-type": 1, "--espspi": 1, "--ahspi": 1, "--ahlen": 1, "--ahres": 0,
    # conntrack, state, helper.
    "--ctstate": 1, "--ctproto": 1, "--ctorigsrc": 1, "--ctorigdst": 1, "--ctreplsrc": 1, "--ctrepldst": 1,
    "--ctorigsrcport": 1, "--ctorigdstport": 1, "--ctreplsrcport": 1, "--ctrepldstport": 1,
    "--ctstatus": 1, "--ctexpire": 1, "--ctdir": 1, "--state": 1, "--helper": 1,
    # comment, mac, physdev, owner, multiport, addrtype, iprange, devgroup.
    "--comment": 1, "--mac-source": 1,
    "--physdev-in": 1, "--physdev-out": 1, "--physdev-is-in": 0, "--physdev-is-out": 0, "--physdev-is-bridged": 0,
    "--uid-owner": 1, "--gid-owner": 1, "--socket-exists": 0, "--suppl-groups": 0,
    "--sports": 1, "--dports": 1, "--ports": 1,
    "--src-type": 1, "--dst-type": 1, "--limit-iface-in": 0, "--limit-iface-out": 0,
    "--src-range": 1, "--dst-range": 1, "--src-group": 1, "--dst-group": 1,
    # limit, hashlimit, connlimit, recent, quota, statistic, nfacct.
    "--limit": 1, "--limit-burst": 1,
    "--hashlimit-upto": 1, "--hashlimit-above": 1, "--hashlimit-burst": 1, "--hashlimit-mode": 1,
    "--hashlimit-srcmask": 1, "--hashlimit-dstmask": 1, "--hashlimit-name": 1, "--hashlimit-htable-size": 1,
    "--hashlimit-htable-max": 1, "--hashlimit-htable-expire": 1, "--hashlimit-htable-gcinterval": 1,
    "--hashlimit-rate-match": 0, "--hashlimit-rate-interval": 1,
    "--connlimit-upto": 1, "--connlimit-above": 1, "--connlimit-mask": 1, "--connlimit-saddr": 0, "--connlimit-daddr": 0,
    "--name": 1, "--set": 0, "--rcheck": 0, "--update": 0, "--remove": 0, "--seconds": 1, "--reap": 0,
    "--hitcount": 1, "--rttl": 0, "--rsource": 0, "--rdest": 0, "--mask": 1,
    "--quota": 1, "--mode": 1, "--probability": 1, "--every": 1, "--packet": 1, "--nfacct-name": 1,
    # mark, connmark, pkttype, length, ttl, hl, tos, dscp, ecn, realm, cgroup, socket, rpfilter, bpf, u32.
    "--mark": 1, "--pkt-type": 1, "--length": 1,
    "--ttl-eq": 1, "--ttl-lt": 1, "--ttl-gt": 1, "--hl-eq": 1, "--hl-lt": 1, "--hl-gt": 1,
    "--tos": 1, "--dscp": 1, "--dscp-class": 1, "--ecn-tcp-cwr": 0, "--ecn-tcp-ece": 0, "--ecn-ip-ect": 1,
    "--realm": 1, "--cgroup": 1, "--path": 1, "--transparent": 0, "--nowildcard": 0, "--restore-skmark": 0,
    "--loose": 0, "--validmark": 0, "--accept-local": 0, "--invert": 0, "--bytecode": 1, "--object-pinned": 1, "--u32": 1,
    # set, string, time, policy.
    "--match-set": 2, "--return-nomatch": 0, "--update-counters": 0, "--update-subcounters": 0,
    "--packets-eq": 1, "--packets-lt": 1, "--packets-gt": 1, "--bytes-eq": 1, "--bytes-lt": 1, "--bytes-gt": 1,
    "--string": 1, "--hex-string": 1, "--algo": 1, "--from": 1, "--to": 1, "--icase": 0,
    "--datestart": 1, "--datestop": 1, "--timestart": 1, "--timestop": 1, "--monthdays": 1, "--weekdays": 1,
    "--contiguous": 0, "--kerneltz": 0,
    "--dir": 1, "--pol": 1, "--strict": 0, "--reqid": 1, "--spi": 1, "--proto": 1,
    "--tunnel-src": 1, "--tunnel-dst": 1, "--next": 0,
    # IPv6 only: rt, ipv6header, frag.
    "--rt-type": 1, "--rt-segsleft": 1, "--rt-len": 1, "--rt-0-res": 0, "--rt-0-addrs": 1, "--rt-0-not-strict": 0,
    "--header": 1, "--soft": 0,
    "--fragid": 1, "--fraglen": 1, "--fragres": 0, "--fragfirst": 0, "--fragmore": 0, "--fraglast": 0,
    # Targets: LOG, NFLOG, REJECT, MARK, CONNMARK, TCPMSS, CLASSIFY, DSCP, TOS, TTL, HL, AUDIT, NFQUEUE, TEE, CHECKSUM.
    "--log-level": 1, "--log-prefix": 1, "--log-tcp-sequence": 0, "--log-tcp-options": 0, "--log-ip-options": 0,
    "--log-uid": 0, "--log-macdecode": 0,
    "--nflog-group": 1, "--nflog-prefix": 1, "--nflog-range": 1, "--nflog-size": 1, "--nflog-threshold": 1,
    "--reject-with": 1,
    "--set-mark": 1, "--set-xmark": 1, "--and-mark": 1, "--or-mark": 1, "--xor-mark": 1,
    "--save-mark": 0, "--restore-mark": 0, "--nfmask": 1, "--ctmask": 1,
    "--set-mss": 1, "--clamp-mss-to-pmtu": 0, "--mss": 1, "--set-class": 1,
    "--set-dscp": 1, "--set-dscp-class": 1, "--set-tos": 1, "--and-tos": 1, "--or-tos": 1, "--xor-tos": 1,
    "--ttl-set": 1, "--ttl-dec": 1, "--ttl-inc": 1, "--hl-set": 1, "--hl-dec": 1, "--hl-inc": 1,
    "--type": 1, "--queue-num": 1, "--queue-balance": 1, "--queue-bypass": 0, "--queue-cpu-fanout": 0,
    "--gateway": 1, "--checksum-fill": 0,
    # Targets of the nat and raw tables, should a listing of those ever be read: DNAT, SNAT, REDIRECT, MASQUERADE, NETMAP, CT, SET.
    "--to-destination": 1, "--to-source": 1, "--to-ports": 1, "--random": 0, "--random-fully": 0, "--persistent": 0,
    "--notrack": 0, "--ctevents": 1, "--expevents": 1, "--zone": 1, "--zone-orig": 1, "--zone-reply": 1, "--timeout": 1,
    "--add-set": 2, "--del-set": 2, "--map-set": 2, "--exist": 0, "--map-mark": 0, "--map-prio": 0, "--map-queue": 0,
}


def split_groups(tokens):
    """A rule's options with their values, in order, and why it could not be read in full.

    Returns (groups, unparsed): groups as [("-i", ["kv+"]), ("! -s",
    ["10.0.0.0/8"]), ...], unparsed as None or one line naming the first
    token the parser had no place for. An option takes the number of tokens
    OPTION_ARITY gives it, so what a value looks like never matters; "!"
    marks a negation only where an option is due. An option the table does
    not know takes the bare tokens after it as a guess, so the rest of the
    rule still reads, and the rule is reported unparsed.
    """
    groups = []
    problems = []
    negate = False
    wanted = 0
    guessing = False
    for token in tokens:
        if wanted:
            groups[-1][1].append(token)
            wanted -= 1
        elif token == "!" and not negate:
            negate = True
        elif token.startswith("-") and len(token) > 1:
            arity = OPTION_ARITY.get(ALIASES.get(token, token))
            groups.append([("! " if negate else "") + token, []])
            negate = False
            if arity is None:
                problems.append(f"option {token} is not one koi-verify-net knows")
                guessing = True
            else:
                wanted = arity
                guessing = False
        elif guessing and not negate:
            groups[-1][1].append(token)
        else:
            # A bare token, or a second "!", where an option is due. Kept
            # in place so the rule's text still reads as the listing did.
            if negate:
                groups.append(["!", []])
                negate = False
            groups.append(["", [token]])
            problems.append(f"{token!r} where an option was expected")
    if wanted:
        problems.append(f"option {groups[-1][0]} is missing a value")
    if negate:
        groups.append(["!", []])
        problems.append("a negation mark with no option after it")
    return [(option, values) for option, values in groups], (problems[0] if problems else None)


def rule_text(tokens):
    """The rule as one line for a message: a negation mark bare, a value quoted where the shell would need it, so a comment of "!" reads as '!'."""
    words = []
    for option, values in split_groups(tokens)[0]:
        if option.startswith("! "):
            words += ["!", option[2:]]
        elif option:
            words.append(option)
        words += [shlex.quote(value) for value in values]
    return " ".join(words)


def normalize_group(option, values):
    """One option group as every spelling of it compares equal: short option names, addresses with their mask, lower case MACs, states in one order."""
    negated = option.startswith("! ")
    name = option[2:] if negated else option
    name = ALIASES.get(name, name)
    if name in ("-s", "-d"):
        normalized = []
        for value in values:
            try:
                normalized.append(str(ipaddress.ip_network(value, strict=False)))
            except ValueError:
                normalized.append(value)
        values = normalized
    elif name == "--mac-source":
        values = [value.lower() for value in values]
    elif name == "--ctstate":
        values = [",".join(sorted(value.split(","))) for value in values]
    elif name == "-p":
        values = [value.lower() for value in values]
    return (("! " + name) if negated else name, tuple(values))


class Rule:
    """One rule, as an argument list without `-A CHAIN`, with the canonical form every spelling of it shares.

    `unparsed` is None, or why the rule could not be read in full; the
    fields below it are then a guess, and attest never calls such a rule
    harmless.
    """

    def __init__(self, tokens, chain=None):
        self.tokens = list(tokens)
        self.chain = chain
        self.text = rule_text(self.tokens)
        groups, self.unparsed = split_groups(self.tokens)
        groups = [normalize_group(option, values) for option, values in groups]
        # iptables loads the tcp or udp match for a port option by itself and
        # prints it, so a rule written without -m tcp is the same rule.
        proto = next((values[0] for option, values in groups if option == "-p" and values), None)
        if proto in ("tcp", "udp") and any(option in PORT_OPTIONS for option, _ in groups) and ("-m", (proto,)) not in groups:
            groups.append(("-m", (proto,)))
        self.groups = groups
        self.canonical = tuple(sorted(groups))
        self.target = self.option("-j")
        self.goto = self.option("-g")
        self.run = None
        comment = self.option("--comment")
        if comment is not None and comment.startswith(COMMENT_PREFIX) and RUN_ID.match(comment[len(COMMENT_PREFIX):]):
            self.run = comment[len(COMMENT_PREFIX):]

    def option(self, name):
        """The first value of a non-negated option, or None."""
        for option, values in self.groups:
            if option == name and values:
                return values[0]
        return None

    def options(self, name):
        """Every value of a non-negated option."""
        return [values[0] for option, values in self.groups if option == name and values]


def canonical(tokens):
    return Rule(tokens).canonical


def parse_listing(text):
    """The rules of an `iptables -S CHAIN` listing, in order; -N and -P lines are not rules."""
    rules = []
    for line in text.splitlines():
        tokens = shlex.split(line)
        if len(tokens) >= 2 and tokens[0] == "-A":
            rules.append(Rule(tokens[2:], chain=tokens[1]))
    return rules


def run_rules(text, run_id):
    """The rules of one run in a listing: those whose comment names it."""
    return [rule for rule in parse_listing(text) if rule.run == run_id]


def delete_command(rule):
    return ["iptables", "-w", "5", "-D", rule.chain, *rule.tokens]


def delete_commands(text, run_id):
    """The commands that remove one run's rules from a chain, from its -S listing, last rule first."""
    return [delete_command(rule) for rule in reversed(run_rules(text, run_id))]


def rule_subnets(rule):
    """The /28 of every address a rule names with -s or -d; the listing prints each with its mask."""
    found = set()
    for value in rule.options("-s") + rule.options("-d"):
        try:
            address = ipaddress.ip_interface(value).ip
        except ValueError:
            continue
        found.add(ipaddress.ip_network(f"{address}/28", strict=False))
    return found


def network_key(network):
    return (network.version, int(network.network_address), network.prefixlen)


# --- The rules of a run -------------------------------------------------------------


def comment(run_id):
    return ["-m", "comment", "--comment", f"{COMMENT_PREFIX}{run_id}"]


def source_match(endpoint, port):
    """The match for traffic from one endpoint: its address, its MAC, and its bridge port when known."""
    match = []
    if port is not None:
        match += ["-m", "physdev", "--physdev-in", port]
    match += ["-m", "mac", "--mac-source", endpoint["mac"]]
    return match


def generate_rules(desc, ports, uid):
    """The run's rules per chain, as iptables argument lists without the chain.

    ports maps a role to the host side of its veth pair, or None while the
    container is not running; uid is koi's, the one host user whose
    connections to the recorder's control port pass. The first rule of each
    chain goes in first, so a chain reads top to bottom as listed here.
    Pure: tests assert the exact output.
    """
    run_id = desc["runId"]
    bridge = desc["bridge"]
    ep = desc["endpoints"]
    tag = comment(run_id)

    def flow(src, dst, dport):
        """A permitted TCP connection from src to dst:dport, and its replies."""
        both = ["-i", bridge, "-o", bridge]
        forward = [
            *both,
            "-s", ep[src]["ip"], "-d", ep[dst]["ip"],
            "-p", "tcp", "-m", "tcp", "--dport", str(dport),
            *source_match(ep[src], ports.get(src)),
            "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED",
            *tag, "-j", "ACCEPT",
        ]
        reply = [
            *both,
            "-s", ep[dst]["ip"], "-d", ep[src]["ip"],
            "-p", "tcp", "-m", "tcp", "--sport", str(dport),
            *source_match(ep[dst], ports.get(dst)),
            "-m", "conntrack", "--ctstate", "ESTABLISHED",
            *tag, "-j", "ACCEPT",
        ]
        return [forward, reply]

    forward_rules = [
        *flow("recorder", "app", desc["appPort"]),
        *flow("verifier", "app", desc["appPort"]),
        *flow("verifier", "recorder", RECORDER_PLAYWRIGHT_PORT),
    ]
    recorder = ep["recorder"]
    input_rules = [
        [
            "-i", bridge, "-s", recorder["ip"],
            "-p", "tcp", "-m", "tcp", "--sport", str(RECORDER_CONTROL_PORT),
            *source_match(recorder, ports.get("recorder")),
            "-m", "conntrack", "--ctstate", "ESTABLISHED",
            *tag, "-j", "ACCEPT",
        ],
    ]
    output_rules = [
        [
            "-o", bridge, "-d", recorder["ip"],
            "-p", "tcp", "-m", "tcp", "--dport", str(RECORDER_CONTROL_PORT),
            "-m", "owner", "--uid-owner", str(uid),
            "-m", "conntrack", "--ctstate", "NEW",
            *tag, "-j", "ACCEPT",
        ],
        [
            "-o", bridge, "-d", recorder["ip"],
            "-p", "tcp", "-m", "tcp", "--dport", str(RECORDER_CONTROL_PORT),
            "-m", "conntrack", "--ctstate", "ESTABLISHED",
            *tag, "-j", "ACCEPT",
        ],
    ]
    return {CHAIN_FORWARD: forward_rules, CHAIN_INPUT: input_rules, CHAIN_OUTPUT: output_rules}


def insert_commands(rules):
    """The iptables commands that install `rules` (generate_rules), in order."""
    commands = []
    for chain, chain_rules in rules.items():
        for position, rule in enumerate(chain_rules, start=1):
            commands.append(["iptables", "-w", "5", "-I", chain, str(position), *rule])
    return commands


def expected_permits(states):
    """The canonical form of every rule an active run's state says it installed, by chain and run.

    A state revoke wrote to recover a subnet describes no rules, so its run
    has none here and any rule still carrying its comment is unknown.
    """
    expected = {}
    for run_id, state in states.items():
        try:
            rules = generate_rules(state, state["ports"], state["uid"])
        except (KeyError, TypeError, AttributeError):
            continue
        for chain, chain_rules in rules.items():
            expected.setdefault(chain, {})[run_id] = {canonical(rule) for rule in chain_rules}
    return expected


def overlapping(subnet, routes, bridge):
    """The first route (from `ip -j route`) that overlaps subnet and is not via the run's own bridge, or None."""
    for route in routes:
        dst = route.get("dst")
        if dst in (None, "default") or route.get("dev") == bridge:
            continue
        try:
            network = ipaddress.ip_network(dst, strict=False)
        except ValueError:
            continue
        if network.version == 4 and network.overlaps(subnet):
            return dst
    return None


def peer_port(container_links, host_links, mac, bridge):
    """The host-side veth of the container interface with `mac`, which must be a port of `bridge`.

    container_links is `ip -j link show` inside the container's namespace,
    host_links the same on the host.
    """
    inside = [link for link in container_links if link.get("address") == mac]
    if len(inside) != 1:
        raise Refused(f"the container has {len(inside)} interfaces with mac {mac}, not one")
    peer = inside[0].get("link_index")
    if not isinstance(peer, int):
        raise Refused(f"the interface with mac {mac} is not one end of a veth pair")
    outside = [link for link in host_links if link.get("ifindex") == peer]
    if len(outside) != 1:
        raise Refused(f"no host interface has index {peer}")
    port = outside[0]
    if port.get("master") != bridge:
        raise Refused(f"{port.get('ifname')} is on {port.get('master') or 'no bridge'}, not {bridge}")
    name = port.get("ifname")
    if not isinstance(name, str) or not IFNAME.match(name):
        raise Refused("the bridge port has a name iptables cannot take")
    return name


# --- Commands --------------------------------------------------------------------


def run_command(argv, stdin=None):
    """Runs argv with a fixed PATH; returns stdout, or raises Failed with the exit code and stderr."""
    try:
        done = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=60,
            env={"PATH": PATH, "LC_ALL": "C"},
            check=False,
        )
    except FileNotFoundError:
        raise Failed(f"{argv[0]} is not installed") from None
    except subprocess.TimeoutExpired:
        raise Failed(f"{' '.join(argv[:3])} timed out") from None
    if done.returncode != 0:
        detail = (done.stderr or done.stdout).strip().splitlines()[-3:]
        raise Failed(
            f"{' '.join(argv[:4])} exited {done.returncode}: {' / '.join(detail)}",
            returncode=done.returncode,
            stderr=done.stderr,
        )
    return done.stdout


def listing(run, chain, table="iptables"):
    """`iptables -S CHAIN`, or None when the chain does not exist."""
    try:
        return run([table, "-w", "5", "-S", chain])
    except Failed as err:
        if "No chain" in str(err) or "does not exist" in str(err):
            return None
        raise


def rules_of(run, chain, table="iptables"):
    """The parsed rules of a chain, or None when it does not exist."""
    text = listing(run, chain, table)
    return None if text is None else parse_listing(text)


class Tables:
    """Chain listings read once each, for one check."""

    def __init__(self, run):
        self.run = run
        self.cache = {}

    def rules(self, table, chain):
        key = (table, chain)
        if key not in self.cache:
            self.cache[key] = rules_of(self.run, chain, table)
        return self.cache[key]


# --- Attestation --------------------------------------------------------------------

KV_BRIDGE = re.compile(r"^kv[0-9a-f]{12}$")
KV_PREFIX = re.compile(r"^kv[0-9a-f]{0,12}$")
# Targets that can only deny or observe: a rule with one of these before a
# koi guard never lets traffic past it.
HARMLESS_TARGETS = frozenset({"DROP", "REJECT", "LOG", "NFLOG"})
MAX_CHAIN_DEPTH = 8


def names_kv(pattern):
    """Whether an -i or -o pattern can name a kv bridge: kv and twelve hex digits, or a wildcard that covers one."""
    if pattern.endswith("+"):
        prefix = pattern[:-1]
        return "kv".startswith(prefix) or KV_PREFIX.match(prefix) is not None
    return KV_BRIDGE.match(pattern) is not None


def may_match_kv(rule, flags):
    """Whether a rule can see traffic of a kv+ interface, judged by its interface options alone.

    Forwarded traffic has an in and an out interface, so a FORWARD rule is
    out of the way only when both exclude kv+. Anything else about a rule
    counts as matching.
    """
    excluded = 0
    for flag in flags:
        value = rule.option(flag)
        if value is not None and not names_kv(value):
            excluded += 1
    return excluded < len(flags)


def bypass(tables, table, rule, flags, stack=()):
    """How a rule before a koi guard could let kv+ traffic past it: its text, or None when it cannot.

    A deny or a log never does. A jump into a user chain is followed, where
    RETURN comes back to the rule after it. An accept, a goto, a RETURN in a
    built-in chain, an extension target, a chain too deep to follow or a
    rule the parser could not read in full could.
    """
    if rule.unparsed is not None:
        return f"{rule.text} (not read in full: {rule.unparsed})"
    if not may_match_kv(rule, flags):
        return None
    if rule.goto is not None:
        return rule.text
    target = rule.target
    if target is None or target in HARMLESS_TARGETS:
        return None
    if target == "RETURN":
        return None if stack else rule.text
    if target == "ACCEPT" or target in stack or len(stack) >= MAX_CHAIN_DEPTH:
        return rule.text
    inner = tables.rules(table, target)
    if inner is None:
        return rule.text
    for nested in inner:
        reason = bypass(tables, table, nested, flags, (*stack, target))
        if reason is not None:
            return f"{rule.text} (chain {target}: {reason})"
    return None


def guard_problem(tables, table, parent, guard, flags, first=False):
    """How `guard` fails to protect kv+ traffic in `parent`: missing, not first when it must be, or behind a rule that could let traffic past. None when it holds."""
    label = f"chain {parent}" if table == "iptables" else f"{table} {parent}"
    rules = tables.rules(table, parent)
    if rules is None:
        return f"{label} does not exist"
    want = canonical(guard)
    for index, rule in enumerate(rules):
        if rule.canonical != want:
            continue
        if first and index > 0:
            return f"{label} does not start with {rule_text(guard)}: its first rule is {rules[0].text}"
        for before in rules[:index]:
            reason = bypass(tables, table, before, flags)
            if reason is not None:
                return f"{label} reaches {rule_text(guard)} only after {reason}"
        return None
    return f"{label} has no rule {rule_text(guard)}"


def permit_problem(rule, chain, states, expected):
    """Why a rule above a chain's defaults is not a permit the helper installed, or None."""
    if rule.unparsed is not None:
        return f"chain {chain} has a rule above its defaults that koi-verify-net cannot read in full ({rule.unparsed}): {rule.text}"
    if rule.run is None:
        return f"chain {chain} has a rule that is not a run permit above its defaults: {rule.text}"
    if rule.run not in states:
        return f"chain {chain} has a permit of run {rule.run}, which has no state file: {rule.text}"
    if rule.canonical not in expected.get(chain, {}).get(rule.run, ()):
        return f"chain {chain} has a permit of run {rule.run} that its state does not describe: {rule.text}"
    return None


def check_ipv4(tables, states):
    """The IPv4 chains, their defaults, the path that reaches them, and that they hold only known permits."""
    problems = []
    chains = defaults = permits = True
    expected = expected_permits(states)
    for spec in CHAINS:
        rules = tables.rules("iptables", spec["chain"])
        if rules is None:
            chains = False
            problems.append(f"chain {spec['chain']} does not exist")
            continue
        base = [canonical(rule) for rule in spec["base"]]
        if [rule.canonical for rule in rules[-len(base):]] == base:
            head = rules[: -len(base)]
        else:
            defaults = False
            problems.append(f"chain {spec['chain']} does not end with its default denies")
            head = rules
        for rule in head:
            problem = permit_problem(rule, spec["chain"], states, expected)
            if problem is not None:
                permits = False
                problems.append(problem)
    jump = True
    guards = [
        ("FORWARD", ["-j", "DOCKER-USER"], ("-i", "-o"), False),
        ("DOCKER-USER", ["-j", CHAIN_FORWARD], ("-i", "-o"), True),
    ]
    for spec in CHAINS[1:]:
        guards.append((spec["parent"], [*spec["match"], "-j", spec["chain"]], spec["flags"], False))
    for parent, guard, flags, first in guards:
        problem = guard_problem(tables, "iptables", parent, guard, flags, first)
        if problem is not None:
            jump = False
            problems.append(problem)
    return {
        "chains": chains,
        "jump": jump,
        "defaults": defaults and chains,
        "permits": permits and chains,
        "problems": problems,
    }


def check_ipv6(tables):
    problems = []
    for parent, rule, flags in BASE_IPV6:
        problem = guard_problem(tables, "ip6tables", parent, rule, flags)
        if problem is not None:
            problems.append(problem)
    return {"defaults": not problems, "problems": problems}


def read_sysctl(name):
    try:
        with open(f"/proc/sys/{name.replace('.', '/')}", encoding="ascii") as f:
            return f.read().strip()
    except OSError:
        return None


def check_sysctl():
    v4 = read_sysctl("net.bridge.bridge-nf-call-iptables")
    v6 = read_sysctl("net.bridge.bridge-nf-call-ip6tables")
    return {
        # The files exist only while br_netfilter is loaded.
        "br_netfilter": v4 is not None,
        "bridge_nf_call_iptables": v4 == "1",
        "bridge_nf_call_ip6tables": v6 == "1",
    }


# --- State files -------------------------------------------------------------------


def state_path(state_dir, run_id):
    return os.path.join(state_dir, f"{run_id}.json")


def write_state(state_dir, run_id, state):
    """Writes the run's state file in one step, readable by root alone."""
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    temp = os.path.join(state_dir, f".{run_id}.tmp")
    with open(os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as f:
        json.dump(state, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, state_path(state_dir, run_id))


def read_state(path):
    """The state file as a dict, or None when there is none. A file that is there but cannot be read is Failed."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as err:
        raise Failed(f"state file {path} is unreadable: {err}") from None
    if not isinstance(data, dict):
        raise Failed(f"state file {path} is unreadable: not an object")
    return data


def state_subnets(state):
    """Every subnet a state file names, as networks."""
    found = set()
    for text in [state.get("subnet"), *(state.get("subnets") or [])]:
        if not isinstance(text, str):
            continue
        try:
            found.add(ipaddress.ip_network(text, strict=False))
        except ValueError:
            pass
    return found


def active_runs(state_dir=None):
    """The state files of applied runs, by run id; None for one that cannot be read."""
    state_dir = STATE_DIR if state_dir is None else state_dir
    runs = {}
    try:
        names = os.listdir(state_dir)
    except FileNotFoundError:
        return runs
    for name in sorted(names):
        if not name.endswith(".json"):
            continue
        run_id = name[: -len(".json")]
        if not RUN_ID.match(run_id):
            continue
        try:
            runs[run_id] = read_state(os.path.join(state_dir, name))
        except Failed:
            runs[run_id] = None
    return runs


def attest(run, env_file=None, state_dir=None):
    env_file = ENV_FILE if env_file is None else env_file
    state_dir = STATE_DIR if state_dir is None else state_dir
    try:
        pool = read_pool(env_file)
    except Refused as err:
        pool = None
        pool_problem = str(err)
    else:
        pool_problem = None
    tables = Tables(run)
    states = active_runs(state_dir)
    ipv4 = check_ipv4(tables, states)
    if pool_problem is not None:
        ipv4["problems"].append(pool_problem)
    rules = {}
    for spec in CHAINS:
        rules[spec["chain"]] = [rule.text for rule in tables.rules("iptables", spec["chain"]) or []]
    return {
        "policy": POLICY_VERSION,
        "pool": None if pool is None else str(pool),
        "ipv4": ipv4,
        "ipv6": check_ipv6(tables),
        "sysctl": check_sysctl(),
        "runs": sorted(states),
        # The bridge port each endpoint's permits are bound to, as the last
        # apply found it. koid will not release a runner on a port of None.
        "ports": {run_id: None if state is None else state.get("ports") for run_id, state in states.items()},
        "rules": rules,
    }


class Lock:
    """One provision, apply or revoke at a time, across processes."""

    def __init__(self, path=None):
        self.path = LOCK_FILE if path is None else path
        self.fd = None

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)
        return False


# --- Provision -----------------------------------------------------------------------


def iptables(run, table, *args):
    return run([table, "-w", "5", *args])


def ensure_guard(run, table, parent, rule, flags, first=False):
    """Puts `rule` where nothing before it in `parent` could let kv+ traffic past (first of all, when `first`).

    A copy goes in at the top before any other copy is removed, so the chain
    never lacks the rule. Returns what changed.
    """
    label = f"chain {parent}" if table == "iptables" else f"{table} {parent}"
    rules = rules_of(run, parent, table)
    if rules is None:
        hint = "; Docker makes it, so Docker must be running" if parent == "DOCKER-USER" else ""
        raise Refused(f"{label} does not exist{hint}")
    changed = []
    if guard_problem(Tables(run), table, parent, rule, flags, first) is not None:
        iptables(run, table, "-I", parent, "1", *rule)
        changed.append(f"{label}: inserted {rule_text(rule)} first")
        rules = rules_of(run, parent, table) or []
    want = canonical(rule)
    copies = [index for index, existing in enumerate(rules) if existing.canonical == want]
    # Later copies go by number, highest first, so the numbers stay right.
    for index in reversed(copies[1:]):
        iptables(run, table, "-D", parent, str(index + 1))
        changed.append(f"{label}: removed a later copy of {rule_text(rule)}")
    return changed


def finish_swap(run, parent, chain, new):
    """The rest of a swap once `new` is reached from `parent`: the jumps to `chain` go, then the chain, and `new` takes its name."""
    for rule in rules_of(run, parent) or []:
        if rule.target == chain:
            iptables(run, "iptables", "-D", parent, *rule.tokens)
    if listing(run, chain) is not None:
        iptables(run, "iptables", "-F", chain)
        iptables(run, "iptables", "-X", chain)
    iptables(run, "iptables", "-E", new, chain)
    return [f"replaced chain {chain}"]


def reconcile_chain(run, spec, parent_rules):
    """Finishes or discards the staged copy of one chain that an interrupted provision left.

    A staged chain the parent already jumps to is the live one, so the swap
    is finished and it takes the chain's name; one nothing reaches is
    removed. Either way, no permit is left in a chain the other commands
    would not look at.
    """
    chain, parent = spec["chain"], spec["parent"]
    new = f"{chain}-NEW"
    if listing(run, new) is None:
        return []
    if any(rule.target == new for rule in parent_rules):
        return finish_swap(run, parent, chain, new)
    iptables(run, "iptables", "-F", new)
    iptables(run, "iptables", "-X", new)
    return [f"removed the unfinished chain {new}"]


def reconcile_swaps(run):
    """Finishes or discards every staged chain, before apply or revoke reads the chains.

    A parent that is missing reaches nothing, so its staged chain is
    discarded; whether the parent must exist is for the host check that
    follows to say.
    """
    changed = []
    for spec in CHAINS:
        changed += reconcile_chain(run, spec, rules_of(run, spec["parent"]) or [])
    return changed


def provision_chain(run, spec):
    """Brings one chain to its run permits followed by its defaults, reached from its parent before anything else.

    A chain that differs is built again beside the old one under a temporary
    name, the parent's jump moves to it, and only then does the old chain
    go, so kv+ traffic is denied by one chain or the other at every step.
    """
    chain, parent, match, base = spec["chain"], spec["parent"], spec["match"], spec["base"]
    new = f"{chain}-NEW"
    changed = []
    parent_rules = rules_of(run, parent)
    if parent_rules is None:
        hint = "; Docker makes it, so Docker must be running" if parent == "DOCKER-USER" else ""
        raise Refused(f"chain {parent} does not exist{hint}")
    changed += reconcile_chain(run, spec, parent_rules)
    current = rules_of(run, chain)
    if current is None:
        iptables(run, "iptables", "-N", chain)
        for rule in base:
            iptables(run, "iptables", "-A", chain, *rule)
        changed.append(f"created chain {chain}")
    else:
        permits = [rule for rule in current if rule.run is not None]
        wanted = [rule.canonical for rule in permits] + [canonical(rule) for rule in base]
        if [rule.canonical for rule in current] != wanted:
            iptables(run, "iptables", "-N", new)
            for rule in permits:
                iptables(run, "iptables", "-A", new, *rule.tokens)
            for rule in base:
                iptables(run, "iptables", "-A", new, *rule)
            iptables(run, "iptables", "-I", parent, "1", *match, "-j", new)
            changed += finish_swap(run, parent, chain, new)
            changed.append(f"rebuilt chain {chain} with {len(permits)} run permits above its defaults")
    changed += ensure_guard(run, "iptables", parent, [*match, "-j", chain], spec["flags"], first=parent == "DOCKER-USER")
    return changed


def provision(run, env_file=None, state_dir=None, lock_file=None):
    """Installs or repairs the chains, the jumps and the IPv6 denies, under the lock apply and revoke take, and reports as attest does."""
    env_file = ENV_FILE if env_file is None else env_file
    state_dir = STATE_DIR if state_dir is None else state_dir
    lock_file = LOCK_FILE if lock_file is None else lock_file
    with Lock(lock_file):
        changed = []
        for spec in CHAINS:
            changed += provision_chain(run, spec)
        for parent, rule, flags in BASE_IPV6:
            changed += ensure_guard(run, "ip6tables", parent, rule, flags)
        report = attest(run, env_file, state_dir)
    return {"changed": changed, "ipv4": report["ipv4"], "ipv6": report["ipv6"], "runs": report["runs"]}


# --- Apply and revoke ----------------------------------------------------------------


def docker_json(run, kind, name):
    """`docker KIND inspect NAME` as one parsed object."""
    text = run(["docker", kind, "inspect", "--format", "{{json .}}", name])
    try:
        return json.loads(text)
    except ValueError:
        raise Failed(f"docker {kind} inspect {name} printed something other than JSON") from None


def check_network(run, desc):
    """The run's Docker network must be the one the descriptor describes."""
    name = network_name(desc["runId"])
    try:
        net = docker_json(run, "network", name)
    except Failed as err:
        raise Refused(f"network {name}: {err}") from None
    options = net.get("Options") or {}
    labels = net.get("Labels") or {}
    subnets = [c.get("Subnet") for c in ((net.get("IPAM") or {}).get("Config") or [])]
    problems = []
    if net.get("Driver") != "bridge":
        problems.append("is not a bridge network")
    if net.get("Internal") is not True:
        problems.append("is not internal")
    if net.get("EnableIPv6") is not False:
        problems.append("has IPv6 enabled")
    if options.get("com.docker.network.bridge.enable_icc") != "false":
        problems.append("lets its containers reach each other")
    if options.get("com.docker.network.bridge.name") != desc["bridge"]:
        problems.append(f"has bridge {options.get('com.docker.network.bridge.name')!r}, not {desc['bridge']}")
    if subnets != [desc["subnet"]]:
        problems.append(f"has subnets {subnets}, not [{desc['subnet']}]")
    if labels.get("koi.run") != desc["runId"]:
        problems.append("is not labelled koi.run for this run")
    if problems:
        raise Refused(f"network {name} {'; '.join(problems)}")


def check_endpoint(run, desc, role):
    """The container's attachment to the run network must match the descriptor.

    Returns the host side of its veth pair when the container runs, else
    None: a container that has not started has no interface yet, and the
    permits bind its address and MAC alone until apply runs again.
    """
    endpoint = desc["endpoints"][role]
    name = endpoint["container"]
    try:
        info = docker_json(run, "container", name)
    except Failed as err:
        raise Refused(f"{role} {name}: {err}") from None
    labels = (info.get("Config") or {}).get("Labels") or {}
    if role == "app":
        if not labels.get("koi.preview"):
            raise Refused(f"app {name} is not a preview container")
    elif labels.get("koi.role") != role or labels.get("koi.run") != desc["runId"]:
        raise Refused(f"{role} {name} is not labelled koi.role={role} koi.run={desc['runId']}")
    networks = (info.get("NetworkSettings") or {}).get("Networks") or {}
    attached = networks.get(network_name(desc["runId"]))
    if attached is None:
        raise Refused(f"{role} {name} is not attached to {network_name(desc['runId'])}")
    running = (info.get("State") or {}).get("Running") is True
    if running:
        if attached.get("IPAddress") != endpoint["ip"]:
            raise Refused(f"{role} {name} has address {attached.get('IPAddress')!r}, not {endpoint['ip']}")
        if attached.get("MacAddress") != endpoint["mac"]:
            raise Refused(f"{role} {name} has mac {attached.get('MacAddress')!r}, not {endpoint['mac']}")
        sandbox = (info.get("NetworkSettings") or {}).get("SandboxKey")
        if not isinstance(sandbox, str) or not sandbox.startswith("/var/run/docker/netns/"):
            raise Refused(f"{role} {name} has no network namespace koi-verify-net can read")
        inside = json.loads(run(["nsenter", f"--net={sandbox}", "--", "ip", "-j", "link", "show"]))
        outside = json.loads(run(["ip", "-j", "link", "show"]))
        return peer_port(inside, outside, endpoint["mac"], desc["bridge"])
    wanted = (attached.get("IPAMConfig") or {}).get("IPv4Address")
    if wanted != endpoint["ip"]:
        raise Refused(f"{role} {name} is configured for address {wanted!r}, not {endpoint['ip']}")
    mac = attached.get("MacAddress") or ""
    if mac not in ("", endpoint["mac"]):
        raise Refused(f"{role} {name} is configured for mac {mac!r}, not {endpoint['mac']}")
    return None


def find_run(run, run_id):
    """Every rule of the run in every KOI-VERIFY chain, staged ones included, in listing order.

    One listing of the whole table, so a chain the helper did not expect
    (a staged copy an interrupted swap left, under any name with the
    prefix) is searched too.
    """
    rules = parse_listing(run(["iptables", "-w", "5", "-S"]))
    return [rule for rule in rules if rule.chain.startswith(CHAIN_PREFIX) and rule.run == run_id]


def remove_run(run, run_id):
    """Deletes every rule of the run in every KOI-VERIFY chain, last first; returns the deleted rules."""
    found = find_run(run, run_id)
    for rule in reversed(found):
        run(delete_command(rule))
    return found


# conntrack exits 1 both when nothing matched and when it failed; only this
# message on stderr says it was the former.
ZERO_FLOWS = re.compile(r"^conntrack v\S+ \(conntrack-tools\): 0 flow entries have been deleted\.$")


def flush_conntrack(run, subnet):
    """Drops the connection tracking entries of every address in the subnet, so no flow outlives its permits."""
    for flag in ("-s", "-d"):
        try:
            run(["conntrack", "-D", flag, str(subnet)])
        except Failed as err:
            if err.returncode == 1 and ZERO_FLOWS.match((err.stderr or "").strip()):
                continue
            raise


def disable_ipv6(bridge):
    path = f"/proc/sys/net/ipv6/conf/{bridge}/disable_ipv6"
    try:
        with open(path, "w", encoding="ascii") as f:
            f.write("1\n")
    except FileNotFoundError:
        # IPv6 is off on the host altogether.
        pass


def koi_uid():
    try:
        return pwd.getpwnam(KOI_USER).pw_uid
    except KeyError:
        raise Refused(f"user {KOI_USER} does not exist") from None


def apply(run, text, env_file=None, state_dir=None, lock_file=None):
    env_file = ENV_FILE if env_file is None else env_file
    state_dir = STATE_DIR if state_dir is None else state_dir
    lock_file = LOCK_FILE if lock_file is None else lock_file
    desc = parse_descriptor(text, read_pool(env_file))
    run_id = desc["runId"]
    with Lock(lock_file):
        # A swap an interrupted provision left would fail the host check
        # and hide permits in a chain under another name; finish it first.
        reconcile_swaps(run)
        states = active_runs(state_dir)
        ipv4 = check_ipv4(Tables(run), states)
        if not (ipv4["chains"] and ipv4["jump"] and ipv4["defaults"] and ipv4["permits"]):
            raise Refused("the host is not as provisioning leaves it: " + "; ".join(ipv4["problems"]))
        subnet = ipaddress.ip_network(desc["subnet"])
        own = states.get(run_id)
        if own is not None and (own.get("subnet") != desc["subnet"] or own.get("bridge") != desc["bridge"]):
            raise Refused(f"run {run_id} already holds {own.get('subnet')} on {own.get('bridge')}; revoke it first")
        for other_id, state in states.items():
            if other_id == run_id or state is None:
                continue
            for other in state_subnets(state):
                if other.overlaps(subnet):
                    raise Refused(f"subnet {subnet} overlaps run {other_id}'s {other}")
            if state.get("bridge") == desc["bridge"]:
                raise Refused(f"bridge {desc['bridge']} belongs to run {other_id}")
        routes = json.loads(run(["ip", "-j", "route", "show"]))
        clash = overlapping(subnet, routes, desc["bridge"])
        if clash is not None:
            raise Refused(f"subnet {subnet} overlaps the host route {clash}")
        check_network(run, desc)
        ports = {role: check_endpoint(run, desc, role) for role in ROLES}
        uid = koi_uid()
        # A second apply for the same run replaces its generation. The old
        # rules go first, and the state changes only once they are gone, so
        # at every instant the rules installed are ones the state describes:
        # attest's permit check compares the two, and a crash that left the
        # old rules in under the new state would make it refuse the host,
        # and so every apply after it. Between the removal and the install
        # the run has no permits at all, the closed side; there is never a
        # moment with both generations.
        remove_run(run, run_id)
        # The state goes in before the first rule, so the subnet to flush is
        # on record before any rule can permit a connection. A later apply
        # keeps the subnet the first one recorded (checked above), and only
        # revoke removes the state.
        write_state(state_dir, run_id, {**desc, "ports": ports, "uid": uid, "policy": POLICY_VERSION})
        rules = generate_rules(desc, ports, uid)
        try:
            for command in insert_commands(rules):
                run(command)
            disable_ipv6(desc["bridge"])
        except Exception:
            # Fail closed: a half-installed generation permits nothing. The
            # state stays, so revoke still flushes the subnet.
            remove_run(run, run_id)
            raise
    count = sum(len(r) for r in rules.values())
    return {"runId": run_id, "rules": count, "ports": ports}


def revoke(run, run_id, state_dir=None, lock_file=None):
    state_dir = STATE_DIR if state_dir is None else state_dir
    lock_file = LOCK_FILE if lock_file is None else lock_file
    if not RUN_ID.match(run_id):
        raise Refused("run id must be 16 to 40 lowercase letters and digits")
    path = state_path(state_dir, run_id)
    with Lock(lock_file):
        # A staged chain an interrupted provision left may be the live one
        # and hold this run's permits; finish or discard the swap before
        # looking for them, so none outlives the flush and the state.
        reconcile_swaps(run)
        found = find_run(run, run_id)
        subnets = set()
        for rule in found:
            subnets |= rule_subnets(rule)
        try:
            state = read_state(path)
        except Failed as err:
            if not found:
                raise Failed(
                    f"{err}, and the chains hold no rule of run {run_id} to recover its subnet from;"
                    " flush its connection tracking entries and remove the file by hand"
                ) from None
            state = None
        if state is None:
            if not found:
                return {"runId": run_id, "removed": 0, "flushed": []}
            # Rules without a state file: an apply or a revoke stopped part
            # way. Record the subnets before any rule goes, so a revoke that
            # stops again still knows what to flush.
            ordered = [str(s) for s in sorted(subnets, key=network_key)]
            write_state(state_dir, run_id, {"runId": run_id, "subnet": ordered[0], "subnets": ordered, "recovered": True})
        else:
            subnets |= state_subnets(state)
        for rule in reversed(found):
            run(delete_command(rule))
        flushed = sorted(subnets, key=network_key)
        for subnet in flushed:
            flush_conntrack(run, subnet)
        # Only now is nothing of the run left to flush.
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    return {"runId": run_id, "removed": len(found), "flushed": [str(s) for s in flushed]}


USAGE = (
    "usage: koi-verify-net apply < descriptor.json | koi-verify-net revoke RUN_ID"
    " | koi-verify-net attest | koi-verify-net provision\n"
)


def main(argv, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr, run=run_command):
    try:
        if argv == ["apply"]:
            result = apply(run, stdin.read(MAX_DESCRIPTOR_BYTES + 1))
        elif len(argv) == 2 and argv[0] == "revoke":
            result = revoke(run, argv[1])
        elif argv == ["attest"]:
            result = attest(run)
        elif argv == ["provision"]:
            result = provision(run)
        else:
            stderr.write(USAGE)
            return 2
    except Refused as err:
        stderr.write(f"koi-verify-net: refused: {err}\n")
        return 2
    except Failed as err:
        stderr.write(f"koi-verify-net: {err}\n")
        return 1
    json.dump(result, stdout)
    stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
