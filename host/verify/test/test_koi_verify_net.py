"""koi-verify-net without root: validation, rule generation, and what provision, apply, revoke and attest run.

The helper runs every command through one function, so these tests hand it
a stand-in for the box: iptables and ip6tables kept in memory, docker and ip
answered from a table, ebtables, the bridge's forwarding table and the
host's neighbours kept in memory too, every call recorded. The stand-in
lists rules the way iptables-nft -S prints them (addresses first and with a mask, interfaces and
protocol next, each match in order, MACs in upper case, the uid numeric, the
comment quoted), so a helper that compared text would fail here as it would
on the box. Nothing here touches iptables, Docker or /run; the one test that
needs root is skipped without it.
"""

import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path

import pytest

HELPER = Path(__file__).parent.parent / "koi_verify_net.py"
spec = importlib.util.spec_from_file_location("koi_verify_net", HELPER)
net = importlib.util.module_from_spec(spec)
spec.loader.exec_module(net)

POOL = net.parse_pool("10.213.0.0/20")
RUN = "abcdefghijklmnop0123"
OTHER = "z" * 16
BRIDGE = "kv0123456789ab"
OTHER_BRIDGE = "kvfedcba987654"
NETWORK = f"koi-v-{RUN}"
APP = "koi-hello-pr-7-aaaaaaaaaaaaaaaa1"
RECORDER = f"koi-verify-{RUN}-recorder"
VERIFIER = f"koi-verify-{RUN}-verifier"
# What the box resolves the koi user to.
KOI_UID = 998
ROUTES = [
    {"dst": "default", "gateway": "172.31.0.1", "dev": "ens5"},
    {"dst": "172.17.0.0/16", "dev": "docker0"},
    {"dst": "172.18.0.0/16", "dev": "koi-previews0"},
    {"dst": "172.31.0.0/20", "dev": "ens5"},
    {"dst": "10.213.0.0/28", "dev": "kvaaaaaaaaaaaa"},
]


def descriptor(**changes):
    d = {
        "version": 1,
        "runId": RUN,
        "bridge": BRIDGE,
        "subnet": "10.213.0.16/28",
        "appPort": 8080,
        "endpoints": [
            {"role": "app", "container": APP, "ip": "10.213.0.18", "mac": "02:42:0a:d5:00:12"},
            {"role": "recorder", "container": RECORDER, "ip": "10.213.0.19", "mac": "02:4b:0a:d5:00:13"},
            {"role": "verifier", "container": VERIFIER, "ip": "10.213.0.20", "mac": "02:4b:0a:d5:00:14"},
        ],
    }
    d.update(changes)
    return d


def other_descriptor():
    """A second run on the next /28, with its own bridge and containers."""
    return descriptor(
        runId=OTHER,
        bridge=OTHER_BRIDGE,
        subnet="10.213.0.32/28",
        endpoints=[
            {"role": "app", "container": "koi-other-pr-8-bbbbbbbbbbbbbbbb2", "ip": "10.213.0.34", "mac": "02:42:0a:d5:00:22"},
            {"role": "recorder", "container": f"koi-verify-{OTHER}-recorder", "ip": "10.213.0.35", "mac": "02:4b:0a:d5:00:23"},
            {"role": "verifier", "container": f"koi-verify-{OTHER}-verifier", "ip": "10.213.0.36", "mac": "02:4b:0a:d5:00:24"},
        ],
    )


def endpoint(d, which, **changes):
    """Descriptor d with one endpoint's fields changed."""
    d["endpoints"] = [dict(e, **changes) if e["role"] == which else e for e in d["endpoints"]]
    return d


def joined(rules):
    return [" ".join(rule) for rule in rules]


def parsed(desc):
    return net.parse_descriptor(json.dumps(desc), POOL)


# --- Listings as iptables-nft prints them -------------------------------------------
#
# Copied from the shape `iptables-nft -S` gives on Ubuntu 24.04 for a
# provisioned box with one run applied, its app and recorder running: the
# helper wrote every rule in another order, without masks, with lower case
# MACs, `--uid-owner koi` and an unquoted comment.

TAG = f'-m comment --comment "koi-run={RUN}"'
LISTING_FORWARD = f"""-N KOI-VERIFY
-A KOI-VERIFY -s 10.213.0.19/32 -d 10.213.0.18/32 -i {BRIDGE} -o {BRIDGE} -p tcp -m tcp --dport 8080 -m physdev --physdev-in vethrecorder --physdev-out vethapp -m mac --mac-source 02:4B:0A:D5:00:13 -m conntrack --ctstate NEW,ESTABLISHED {TAG} -j ACCEPT
-A KOI-VERIFY -s 10.213.0.18/32 -d 10.213.0.19/32 -i {BRIDGE} -o {BRIDGE} -p tcp -m tcp --sport 8080 -m physdev --physdev-in vethapp --physdev-out vethrecorder -m mac --mac-source 02:42:0A:D5:00:12 -m conntrack --ctstate ESTABLISHED {TAG} -j ACCEPT
-A KOI-VERIFY -s 10.213.0.20/32 -d 10.213.0.18/32 -i {BRIDGE} -o {BRIDGE} -p tcp -m tcp --dport 8080 -m physdev --physdev-out vethapp -m mac --mac-source 02:4B:0A:D5:00:14 -m conntrack --ctstate NEW,ESTABLISHED {TAG} -j ACCEPT
-A KOI-VERIFY -s 10.213.0.18/32 -d 10.213.0.20/32 -i {BRIDGE} -o {BRIDGE} -p tcp -m tcp --sport 8080 -m physdev --physdev-in vethapp -m mac --mac-source 02:42:0A:D5:00:12 -m conntrack --ctstate ESTABLISHED {TAG} -j ACCEPT
-A KOI-VERIFY -s 10.213.0.20/32 -d 10.213.0.19/32 -i {BRIDGE} -o {BRIDGE} -p tcp -m tcp --dport 4317 -m physdev --physdev-out vethrecorder -m mac --mac-source 02:4B:0A:D5:00:14 -m conntrack --ctstate NEW,ESTABLISHED {TAG} -j ACCEPT
-A KOI-VERIFY -s 10.213.0.19/32 -d 10.213.0.20/32 -i {BRIDGE} -o {BRIDGE} -p tcp -m tcp --sport 4317 -m physdev --physdev-in vethrecorder -m mac --mac-source 02:4B:0A:D5:00:13 -m conntrack --ctstate ESTABLISHED {TAG} -j ACCEPT
-A KOI-VERIFY -i kv+ -m conntrack --ctstate INVALID -j DROP
-A KOI-VERIFY -o kv+ -m conntrack --ctstate INVALID -j DROP
-A KOI-VERIFY -i kv+ -p udp -j DROP
-A KOI-VERIFY -d 224.0.0.0/4 -i kv+ -j DROP
-A KOI-VERIFY -d 169.254.0.0/16 -i kv+ -j DROP
-A KOI-VERIFY -i kv+ -p tcp -m tcp --dport 53 -j DROP
-A KOI-VERIFY -i kv+ -j DROP
-A KOI-VERIFY -o kv+ -j DROP
"""
LISTING_INPUT_CHAIN = f"""-N KOI-VERIFY-IN
-A KOI-VERIFY-IN -s 10.213.0.19/32 -i {BRIDGE} -p tcp -m tcp --sport 4318 -m physdev --physdev-in vethrecorder -m mac --mac-source 02:4B:0A:D5:00:13 -m conntrack --ctstate ESTABLISHED {TAG} -j ACCEPT
-A KOI-VERIFY-IN -m conntrack --ctstate INVALID -j DROP
-A KOI-VERIFY-IN -p udp -j DROP
-A KOI-VERIFY-IN -j DROP
"""
LISTING_OUTPUT_CHAIN = f"""-N KOI-VERIFY-OUT
-A KOI-VERIFY-OUT -d 10.213.0.19/32 -o {BRIDGE} -p tcp -m tcp --dport 4318 -m owner --uid-owner {KOI_UID} -m conntrack --ctstate NEW {TAG} -j ACCEPT
-A KOI-VERIFY-OUT -d 10.213.0.19/32 -o {BRIDGE} -p tcp -m tcp --dport 4318 -m conntrack --ctstate ESTABLISHED {TAG} -j ACCEPT
-A KOI-VERIFY-OUT -m conntrack --ctstate INVALID -j DROP
-A KOI-VERIFY-OUT -p udp -j DROP
-A KOI-VERIFY-OUT -j DROP
"""
LISTING_DOCKER_USER = """-N DOCKER-USER
-A DOCKER-USER -j KOI-VERIFY
-A DOCKER-USER -d 169.254.169.254/32 -j DROP
-A DOCKER-USER -j RETURN
"""
LISTING_INPUT = """-P INPUT ACCEPT
-A INPUT -i kv+ -j KOI-VERIFY-IN
-A INPUT -i koi-previews0 -p tcp -m tcp --dport 3128 -m conntrack --ctstate NEW -j ACCEPT
-A INPUT -i koi-build0 -m conntrack --ctstate NEW -j DROP
-A INPUT -i koi-previews0 -m conntrack --ctstate NEW -j DROP
"""
# Written by hand, as iptables-nft -S prints such rules; no stand-in renders
# them. A comment is any text, quoted only when it holds a character outside
# [A-Za-z0-9_-], so "!" comes out quoted and "-j" bare: only the one value
# --comment takes says where the comment ends. The fourth rule is a real
# negation, where "!" stands before an option.
LISTING_INPUT_ODD = """-P INPUT ACCEPT
-A INPUT -i kv+ -m comment --comment "!" -j ACCEPT
-A INPUT -i kv+ -m comment --comment "a comment, with spaces and \\"quotes\\" and -j DROP in it" -j ACCEPT
-A INPUT -i kv+ -m comment --comment -j -j ACCEPT
-A INPUT ! -i kv+ -j ACCEPT
-A INPUT -i kv+ -j KOI-VERIFY-IN
"""
ODD_COMMENTS = ["!", 'a comment, with spaces and "quotes" and -j DROP in it', "-j"]


def with_mask(value):
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return value


# How many values each option the tests write takes, as iptables knows it.
# The stand-in takes values by position, as iptables does, so a comment of
# "!" or "-j" is a comment; it refuses an option not here rather than guess.
ARITY = {
    "-s": 1, "-d": 1, "-i": 1, "-o": 1, "-p": 1, "-m": 1, "-j": 1, "-g": 1,
    "--dport": 1, "--sport": 1, "--ctstate": 1, "--comment": 1, "--mac-source": 1,
    "--physdev-in": 1, "--physdev-out": 1, "--uid-owner": 1, "--set-mark": 1,
}


def group(tokens):
    """Options with their values, each taking the number of tokens ARITY says: [("-i", ["kv+"]), ("! -s", ["10.0.0.0/8"]), ...]."""
    groups = []
    negate = ""
    wanted = 0
    for token in tokens:
        if wanted:
            groups[-1][1].append(token)
            wanted -= 1
        elif token == "!":
            negate = "! "
        else:
            assert token in ARITY, f"the fake firewall does not know the option {token!r} in: {' '.join(tokens)}"
            groups.append([negate + token, []])
            negate = ""
            wanted = ARITY[token]
    assert not wanted and not negate, f"the rule ends short: {' '.join(tokens)}"
    return groups


def render(tokens):
    """A rule's tokens as iptables-nft -S prints them.

    -s and -d first, with their mask; then -i, -o and -p; then each match
    with its options in the order given, a port option loading -m tcp or
    -m udp by itself; then the target. MACs come out upper case, a user
    name as its uid.
    """
    groups = group(tokens)
    head = {}
    matches = []
    tail = []
    current = None
    proto = None
    for option, values in groups:
        name = option.lstrip("! ")
        if tail:
            # An option after the target is the target's, as --set-mark is MARK's.
            tail += [option, *values]
        elif name in ("-s", "-d"):
            head[name] = (option, [with_mask(v) for v in values])
        elif name in ("-i", "-o", "-p"):
            head[name] = (option, values)
            if name == "-p":
                proto = values[0]
        elif name == "-m":
            current = [(option, values)]
            matches.append(current)
        elif name in ("-j", "-g"):
            tail = [option, *values]
        else:
            if name in ("--dport", "--sport") and (current is None or current[0][1] != [proto]):
                current = [("-m", [proto])]
                matches.append(current)
            if name == "--mac-source":
                values = [v.upper() for v in values]
            if name == "--uid-owner":
                values = [str(KOI_UID) if v == "koi" else v for v in values]
            current.append((option, values))
    out = []
    for name in ("-s", "-d", "-i", "-o", "-p"):
        if name in head:
            option, values = head[name]
            out += option.split(" ") + values
    for match in matches:
        for option, values in match:
            out += option.split(" ") + values
    return out + tail


def saved_string(value):
    """xtables_save_string: bare when only letters, digits, _ and -; else in double quotes with escapes."""
    if value and all(c.isascii() and (c.isalnum() or c in "_-") for c in value):
        return value
    escaped = "".join("\\" + c if c in "\"\\'" else c for c in value)
    return f'"{escaped}"'


def rule_line(chain, tokens):
    words = []
    for index, token in enumerate(tokens):
        words.append(saved_string(token) if index > 0 and tokens[index - 1] == "--comment" else token)
    return f"-A {chain} {' '.join(words)}"


class Firewall:
    """iptables and ip6tables in memory, as Docker and koi-firewall leave them before provision runs."""

    BUILTIN = ("INPUT", "FORWARD", "OUTPUT")

    def __init__(self):
        self.tables = {}
        for table in ("iptables", "ip6tables"):
            chains = {name: [] for name in self.BUILTIN}
            chains["FORWARD"] = [render(["-j", "DOCKER-USER"]), render(["-j", "DOCKER-ISOLATION-STAGE-1"])]
            chains["DOCKER-USER"] = [render(["-j", "RETURN"])]
            chains["DOCKER-ISOLATION-STAGE-1"] = [render(["-j", "RETURN"])]
            self.tables[table] = chains
        # koi-firewall's own rules, which go in before the helper runs.
        self.tables["iptables"]["DOCKER-USER"].insert(0, render("-d 169.254.169.254 -j DROP".split()))
        self.tables["ip6tables"]["DOCKER-USER"].insert(0, render("-d fd00:ec2::254 -j DROP".split()))
        self.tables["iptables"]["INPUT"] = [
            render("-i koi-previews0 -p tcp --dport 3128 -m conntrack --ctstate NEW -j ACCEPT".split()),
            render("-i koi-build0 -m conntrack --ctstate NEW -j DROP".split()),
            render("-i koi-previews0 -m conntrack --ctstate NEW -j DROP".split()),
        ]
        # Kernel 7.0 with iptables-nft 1.8.10: a missing chain is reported as
        # "Incompatible with this kernel", not "No chain".
        self.incompatible = False
        # While watching, every change is followed by a check that kv+
        # traffic is still denied; the commands after which it was not.
        self.watching = False
        self.unconfined_after = []
        self.checks = 0

    def header(self, chain):
        return f"-P {chain} ACCEPT" if chain in self.BUILTIN else f"-N {chain}"

    def listing(self, table, chain):
        rules = self.tables[table][chain]
        return "".join([f"{self.header(chain)}\n"] + [f"{rule_line(chain, r)}\n" for r in rules])

    def whole(self, table):
        """`iptables -S` with no chain: every chain's header, then every chain's rules."""
        chains = self.tables[table]
        lines = [self.header(chain) for chain in chains]
        lines += [rule_line(chain, r) for chain, rules in chains.items() for r in rules]
        return "".join(f"{line}\n" for line in lines)

    def command(self, table, argv):
        """One iptables command after `-w 5`; returns its output or raises Failed as the real one exits."""
        chains = self.tables[table]
        op = argv[0]
        chain = argv[1] if len(argv) > 1 else None

        def fail(message, code=1):
            raise net.Failed(f"{table} -w 5 {op} exited {code}: {message}", returncode=code, stderr=message + "\n")

        if op == "-S":
            if chain is None:
                return self.whole(table)
            if chain not in chains:
                fail(f"{table}: Incompatible with this kernel." if self.incompatible else "iptables: No chain/target/match by that name.")
            return self.listing(table, chain)
        if op == "-C":
            if chain not in chains:
                fail("iptables: No chain/target/match by that name.")
            if render(argv[2:]) not in chains[chain]:
                fail("iptables: Bad rule (does a matching rule exist in that chain?).")
            return ""
        if op == "-N":
            if chain in chains:
                fail("iptables: Chain already exists.")
            chains[chain] = []
        elif op == "-X":
            if chain not in chains:
                fail("iptables: No chain/target/match by that name.")
            if chains[chain]:
                fail("iptables: Directory not empty.")
            if any(r[-2:] == ["-j", chain] or r[-2:] == ["-g", chain] for rules in chains.values() for r in rules):
                fail("iptables: Too many links.")
            del chains[chain]
        elif op == "-F":
            if chain not in chains:
                fail("iptables: No chain/target/match by that name.")
            chains[chain].clear()
        elif op == "-E":
            old, new = argv[1], argv[2]
            if old not in chains:
                fail("iptables: No chain/target/match by that name.")
            if new in chains:
                fail("iptables: File exists.")
            chains[new] = chains.pop(old)
            for rules in chains.values():
                for r in rules:
                    if r[-2:] == ["-j", old]:
                        r[-1] = new
        elif op == "-A":
            if chain not in chains:
                fail("iptables: No chain/target/match by that name.")
            chains[chain].append(render(argv[2:]))
        elif op == "-I":
            if chain not in chains:
                fail("iptables: No chain/target/match by that name.")
            rest = argv[2:]
            position = 1
            if rest and rest[0].isdigit():
                position = int(rest[0])
                rest = rest[1:]
            if not 1 <= position <= len(chains[chain]) + 1:
                fail("iptables: Index of insertion too big.")
            chains[chain].insert(position - 1, render(rest))
        elif op == "-D":
            if chain not in chains:
                fail("iptables: No chain/target/match by that name.")
            rest = argv[2:]
            if len(rest) == 1 and rest[0].isdigit():
                index = int(rest[0])
                if not 1 <= index <= len(chains[chain]):
                    fail("iptables: Index of deletion too big.")
                del chains[chain][index - 1]
            else:
                wanted = render(rest)
                if wanted not in chains[chain]:
                    fail("iptables: Bad rule (does a matching rule exist in that chain?).")
                chains[chain].remove(wanted)
        else:
            raise AssertionError(f"the fake firewall does not know {table} {' '.join(argv)}")
        if self.watching:
            self.checks += 1
            if not self.confined():
                self.unconfined_after.append(f"{table} {' '.join(argv)}")
        return ""

    def confined(self):
        """Whether kv+ traffic is denied right now: DOCKER-USER, INPUT and OUTPUT each reach a chain that ends in the denies before anything that could accept it."""
        chains = self.tables["iptables"]

        def ends_in(chain, tail):
            rules = chains.get(chain)
            if rules is None:
                return False
            # A REJECT denies as a DROP does.
            last = [r[:-1] + ["DROP"] if r[-1] == "REJECT" else r for r in rules[-len(tail):]]
            return last == tail

        def guarded(parent, match, tail):
            for rule in chains[parent]:
                options = {option: values for option, values in group(rule)}
                if "-j" not in options:
                    continue
                target = options["-j"][0]
                if target in ("DROP", "REJECT", "LOG"):
                    continue
                if rule[:-2] == match and ends_in(target, tail):
                    return True
                if match and match[0] in options:
                    interface = options[match[0]][0]
                    if not (interface.endswith("+") or interface.startswith("kv")):
                        continue
                # Anything else that could see kv+ traffic comes first.
                return False
            return False

        forward_tail = [render("-i kv+ -j DROP".split()), render("-o kv+ -j DROP".split())]
        return (
            guarded("DOCKER-USER", [], forward_tail)
            and guarded("INPUT", ["-i", "kv+"], [["-j", "DROP"]])
            and guarded("OUTPUT", ["-o", "kv+"], [["-j", "DROP"]])
        )


ETHERTYPE_NAMES = {"0x0800": "IPv4", "0x0806": "ARP"}


class Bridges:
    """ebtables' filter table, the bridges' forwarding entries and the host's IPv4 neighbours, as the tools print them."""

    def __init__(self):
        self.ebtables = {"INPUT": [], "FORWARD": [], "OUTPUT": []}
        self.fdb = []
        self.neigh = []

    def ebtables_listing(self):
        """`ebtables -t filter -L` as ebtables-nft prints it: a header per chain, its rules, a blank line."""
        out = ["Bridge table: filter", ""]
        for name, rules in self.ebtables.items():
            policy = "ACCEPT" if name in ("INPUT", "FORWARD", "OUTPUT") else "RETURN"
            out.append(f"Bridge chain: {name}, entries: {len(rules)}, policy: {policy}")
            out += [" ".join(r) for r in rules]
            out.append("")
        return "\n".join(out) + "\n"

    def ebtables_command(self, argv):
        """One ebtables command after `-t filter`; raises Failed as the real one exits."""
        op, chain = argv[0], argv[1] if len(argv) > 1 else None

        def fail():
            raise net.Failed(f"ebtables -t filter {op} exited 1: ebtables: No chain/target/match by that name", returncode=1)

        if op == "-L":
            return self.ebtables_listing()
        if chain not in self.ebtables and op != "-N":
            fail()
        rule = [ETHERTYPE_NAMES.get(t, t) for t in argv[2:]]
        if op == "-N":
            self.ebtables[chain] = []
        elif op == "-A":
            self.ebtables[chain].append(rule)
        elif op == "-I":
            self.ebtables[chain].insert(int(rule[0]) - 1, rule[1:])
        elif op == "-D":
            del self.ebtables[chain][int(rule[0]) - 1]
        else:
            raise AssertionError(f"the fake ebtables does not know {' '.join(argv)}")
        return ""

    def bridge_command(self, argv, links):
        """`bridge fdb replace|del`: a static entry is listed once for VLAN 1 and once without, as on the box."""
        op, mac, port = argv[2], argv[3], argv[5]
        master = next((link.get("master") for link in links if link.get("ifname") == port), None)
        if master is None:
            raise net.Failed(f"bridge fdb {op} exited 255: Error: argument \"{port}\" is wrong: Device does not exist", returncode=255)
        if op == "replace":
            self.fdb = [e for e in self.fdb if not (e["mac"] == mac and e.get("master") == master)]
            for vlan in (1, None):
                entry = {"mac": mac, "ifname": port, "flags": ["sticky"], "master": master, "state": "static"}
                if vlan is not None:
                    entry["vlan"] = vlan
                self.fdb.append(entry)
        elif op == "del":
            kept = [e for e in self.fdb if not (e["mac"] == mac and e["ifname"] == port)]
            if len(kept) == len(self.fdb):
                raise net.Failed("bridge fdb del exited 255: RTNETLINK answers: No such file or directory", returncode=255)
            self.fdb = kept
        else:
            raise AssertionError(f"the fake bridge does not know {' '.join(argv)}")
        return ""

    def neigh_command(self, argv):
        """`ip neigh replace ADDRESS lladdr MAC dev BRIDGE nud permanent` and `ip neigh del ADDRESS dev BRIDGE`."""
        op, address = argv[2], argv[3]
        dev = argv[argv.index("dev") + 1]
        rest = [e for e in self.neigh if not (e["dst"] == address and e["dev"] == dev)]
        if op == "replace":
            self.neigh = rest + [{"dst": address, "dev": dev, "lladdr": argv[argv.index("lladdr") + 1], "state": ["PERMANENT"]}]
        elif op == "del":
            if len(rest) == len(self.neigh):
                raise net.Failed("ip neigh del exited 2: RTNETLINK answers: No such file or directory", returncode=2)
            self.neigh = rest
        else:
            raise AssertionError(f"the fake ip does not know {' '.join(argv)}")
        return ""

    def learned(self, mac, port, master):
        """A frame from `mac` came in on `port`: the bridge learns it there, unless the entry is sticky."""
        for entry in self.fdb:
            if entry["mac"] == mac and entry.get("master") == master and "sticky" in entry["flags"]:
                return
        self.fdb = [e for e in self.fdb if not (e["mac"] == mac and e.get("master") == master)]
        self.fdb.append({"mac": mac, "ifname": port, "flags": [], "master": master, "state": ""})


class Crash(BaseException):
    """The helper's process dying at a command: not an Exception, so nothing in the helper catches it."""


class Box:
    """The box: the firewall in memory, docker and ip answered from a table, every call recorded."""

    def __init__(self, tmp_path, provisioned=True):
        self.calls = []
        self.answers = {}
        self.failing = {}
        self.env = tmp_path / "env"
        self.env.write_text("KOI_VERIFY_POOL=10.213.0.0/20\n")
        self.state = tmp_path / "state"
        self.lock = tmp_path / "lock"
        self.fw = Firewall()
        self.l2 = Bridges()
        self.links = []
        self.answers["ip -j route show"] = json.dumps(ROUTES)
        # The flushes asked of conntrack, and what it answers besides "0 flows".
        self.conntrack = []
        self.conntrack_error = None
        # Whether the run's state file existed when its first rule went in,
        # and what it held when its last rule was deleted.
        self.state_at_first_insert = None
        self.state_at_last_delete = None
        # Die before the n-th command that changes something, counted from
        # zero, as a kill would; None never dies.
        self.crash_before = None
        if provisioned:
            self.provision()
            self.calls.clear()

    def docker(self, desc, running=()):
        """Docker as koid leaves it before apply: the network made, the app connected, the helpers created."""
        run_id = desc["runId"]
        network = f"koi-v-{run_id}"
        subnet = ipaddress.ip_network(desc["subnet"])
        self.answers[f"docker network inspect --format {{{{json .}}}} {network}"] = json.dumps(
            {
                "Name": network,
                "Driver": "bridge",
                "Internal": True,
                "EnableIPv6": False,
                "Options": {"com.docker.network.bridge.enable_icc": "false", "com.docker.network.bridge.name": desc["bridge"]},
                "Labels": {"koi.run": run_id},
                "IPAM": {"Config": [{"Subnet": desc["subnet"], "Gateway": str(subnet[1])}]},
            }
        )
        base = 100 * (len(self.links) // 3 + 1)
        # Each run's ports have names of their own, as on the box.
        others = {link.get("master") for link in self.links if link.get("master") not in (None, desc["bridge"])}
        suffix = str(len(others) + 1) if others else ""
        for e in desc["endpoints"]:
            role = e["role"]
            labels = {"koi.preview": "hello-pr-7"} if role == "app" else {"koi.role": role, "koi.run": run_id}
            attached = {
                "IPAddress": e["ip"] if role in running else "",
                "MacAddress": e["mac"],
                "IPAMConfig": {"IPv4Address": e["ip"]},
            }
            networks = {network: attached}
            if role == "app":
                networks["koi-previews"] = {"IPAddress": "172.18.0.5"}
            self.answers[f"docker container inspect --format {{{{json .}}}} {e['container']}"] = json.dumps(
                {
                    "State": {"Running": role in running},
                    "Config": {"Labels": labels},
                    "NetworkSettings": {
                        "SandboxKey": f"/var/run/docker/netns/{role}" if role in running else "",
                        "Networks": networks,
                    },
                }
            )
            self.answers[f"nsenter --net=/var/run/docker/netns/{role} -- ip -j link show"] = json.dumps(
                [{"ifindex": 10, "link_index": base + net.OFFSETS[role], "ifname": "eth0", "address": e["mac"]}]
            )
            self.links.append({"ifindex": base + net.OFFSETS[role], "ifname": f"veth{role}{suffix}", "master": desc["bridge"]})
        if not any(link.get("ifname") == desc["bridge"] for link in self.links):
            self.links.append({"ifindex": base, "ifname": desc["bridge"]})

    def inspected(self, name):
        key = f"docker {'network' if name.startswith('koi-v-') else 'container'} inspect --format {{{{json .}}}} {name}"
        return key, json.loads(self.answers[key])

    def run(self, argv, stdin=None):
        line = " ".join(argv)
        self.calls.append(line)
        if line in self.failing:
            failure = self.failing[line]
            raise failure if isinstance(failure, Exception) else net.Failed(failure)
        if line in self.answers:
            return self.answers[line]
        if self.crash_before is not None and self.is_change(argv):
            if self.crash_before == 0:
                raise Crash(line)
            self.crash_before -= 1
        if argv[0] in ("iptables", "ip6tables") and argv[1:3] == ["-w", "5"]:
            if argv[3] == "-I" and argv[4].startswith("KOI-VERIFY") and self.state_at_first_insert is None:
                self.state_at_first_insert = (self.state / f"{RUN}.json").exists()
            if argv[3] == "-D" and argv[4].startswith("KOI-VERIFY") and (self.state / f"{RUN}.json").exists():
                self.state_at_last_delete = json.loads((self.state / f"{RUN}.json").read_text())
            return self.fw.command(argv[0], argv[3:])
        if line == "ip -j link show":
            return json.dumps(self.links)
        if argv[0] == "ebtables" and argv[1:3] == ["-t", "filter"]:
            return self.l2.ebtables_command(argv[3:])
        if line == "bridge -j fdb show":
            return json.dumps(self.l2.fdb)
        if argv[:2] == ["bridge", "fdb"]:
            return self.l2.bridge_command(argv, self.links)
        if line == "ip -4 -j neigh show":
            return json.dumps(self.l2.neigh)
        if argv[:2] == ["ip", "neigh"]:
            return self.l2.neigh_command(argv)
        if argv[0] == "conntrack":
            self.conntrack.append(line)
            if self.conntrack_error is not None:
                raise self.conntrack_error
            message = "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted."
            raise net.Failed(f"conntrack -D {argv[2]} {argv[3]} exited 1: {message}", returncode=1, stderr=message + "\n")
        raise AssertionError(f"unexpected command: {line}")

    def provision(self):
        return net.provision(self.run, env_file=self.env, state_dir=self.state, lock_file=self.lock)

    def apply(self, desc):
        return net.apply(self.run, json.dumps(desc), env_file=self.env, state_dir=self.state, lock_file=self.lock)

    def revoke(self, run_id):
        return net.revoke(self.run, run_id, state_dir=self.state, lock_file=self.lock)

    def attest(self):
        return net.attest(self.run, env_file=self.env, state_dir=self.state)

    def rules(self, chain, table="iptables"):
        """The chain's rules as the fake holds them: rendered token lists."""
        return self.fw.tables[table][chain]

    def listing(self, chain, table="iptables"):
        return self.fw.listing(table, chain)

    @staticmethod
    def is_change(argv):
        """Whether the command changes something: conntrack, an iptables or ebtables call that is not a listing or a check, a pin."""
        if argv[0] == "conntrack":
            return True
        if argv[0] in ("iptables", "ip6tables"):
            return argv[3] not in ("-S", "-C")
        if argv[0] == "ebtables":
            return argv[3] != "-L"
        return argv[:2] in (["bridge", "fdb"], ["ip", "neigh"])

    def changes(self):
        """The calls that change something, in order."""
        return [call for call in self.calls if self.is_change(call.split())]

    def clean(self):
        return all(self.rules(spec["chain"]) == [render(r) for r in spec["base"]] for spec in net.CHAINS)

    def pins(self):
        """The static entries as (mac, port), and the permanent neighbours as (address, mac)."""
        fdb = sorted({(e["mac"], e["ifname"]) for e in self.l2.fdb if e["state"] == "static"})
        neigh = sorted((e["dst"], e["lladdr"]) for e in self.l2.neigh if "PERMANENT" in e["state"])
        return fdb, neigh

    def state_file(self, run_id=RUN):
        return self.state / f"{run_id}.json"


@pytest.fixture
def box(tmp_path, monkeypatch):
    # The bridge's IPv6 switch and the sysctls live in /proc; the koi user in
    # /etc/passwd. Nothing to read or write here.
    monkeypatch.setattr(net, "disable_ipv6", lambda bridge: None)
    monkeypatch.setattr(net, "read_sysctl", lambda name: "1")
    monkeypatch.setattr(net, "write_sysctl", lambda name, value: pytest.fail(f"wrote {name}"))
    monkeypatch.setattr(net, "koi_uid", lambda: KOI_UID)
    return Box(tmp_path)


@pytest.fixture
def bare(tmp_path, monkeypatch):
    """A box before provision has run."""
    monkeypatch.setattr(net, "disable_ipv6", lambda bridge: None)
    monkeypatch.setattr(net, "read_sysctl", lambda name: "1")
    monkeypatch.setattr(net, "write_sysctl", lambda name, value: pytest.fail(f"wrote {name}"))
    monkeypatch.setattr(net, "koi_uid", lambda: KOI_UID)
    return Box(tmp_path, provisioned=False)


def installed(desc, ports):
    return net.generate_rules(parsed(desc), ports, KOI_UID)


# --- Pure functions ------------------------------------------------------------------


class TestDescriptor:
    def test_accepts_the_shape_koid_sends(self):
        p = parsed(descriptor())
        assert p["runId"] == RUN
        assert p["bridge"] == BRIDGE
        assert p["subnet"] == "10.213.0.16/28"
        assert p["gateway"] == "10.213.0.17"
        assert p["appPort"] == 8080
        assert p["endpoints"]["recorder"] == {"container": RECORDER, "ip": "10.213.0.19", "mac": "02:4b:0a:d5:00:13"}

    @pytest.mark.parametrize(
        "text, message",
        [
            ("not json", "not JSON"),
            ("[]", "not an object"),
            (json.dumps({**descriptor(), "extra": 1}), r"unknown \['extra'\]"),
            (json.dumps({k: v for k, v in descriptor().items() if k != "appPort"}), r"missing \['appPort'\]"),
            (json.dumps(descriptor(version=2)), "version must be 1"),
            (json.dumps(descriptor(runId="UPPER-not-allowed")), "runId"),
            (json.dumps(descriptor(runId="short")), "runId"),
            (json.dumps(descriptor(bridge="docker0")), "bridge must be kv"),
            (json.dumps(descriptor(bridge="kv0123456789abc")), "bridge must be kv"),
            (json.dumps(descriptor(bridge="kv0123456789a;")), "bridge must be kv"),
            (json.dumps(descriptor(subnet="10.213.0.16/29")), "must be an IPv4 /28"),
            (json.dumps(descriptor(subnet="10.213.0.17/28")), "subnet: "),
            (json.dumps(descriptor(subnet="10.214.0.16/28")), "outside the reserved pool"),
            (json.dumps(descriptor(subnet="fd00::/28")), "must be an IPv4 /28"),
            (json.dumps(descriptor(appPort=0)), "appPort"),
            (json.dumps(descriptor(appPort="8080")), "appPort"),
            (json.dumps(descriptor(appPort=True)), "appPort"),
            (json.dumps(descriptor(endpoints=descriptor()["endpoints"][:2])), "exactly three"),
        ],
    )
    def test_refuses_a_descriptor_of_the_wrong_shape(self, text, message):
        with pytest.raises(net.Refused, match=message):
            net.parse_descriptor(text, POOL)

    def test_refuses_endpoints_that_are_not_the_three_fixed_addresses(self):
        with pytest.raises(net.Refused, match="ip must be 10.213.0.19"):
            parsed(endpoint(descriptor(), "recorder", ip="10.213.0.21"))
        d = descriptor()
        d["endpoints"][2] = dict(d["endpoints"][1])
        with pytest.raises(net.Refused, match="appears twice"):
            parsed(d)
        with pytest.raises(net.Refused, match="not one of app, recorder, verifier"):
            parsed(endpoint(descriptor(), "verifier", role="host"))
        with pytest.raises(net.Refused, match="exactly role, container, ip and mac"):
            parsed(endpoint(descriptor(), "verifier", port="veth1"))

    @pytest.mark.parametrize(
        "mac, message",
        [
            ("02:4b:0a:d5:00", "six lowercase hex pairs"),
            ("02:4B:0A:D5:00:14", "six lowercase hex pairs"),
            ("00:4b:0a:d5:00:14", "locally administered"),
            ("03:4b:0a:d5:00:14", "locally administered"),
            ("02:4b:0a:d5:00:13", "share a mac"),
        ],
    )
    def test_refuses_a_mac_that_is_not_a_local_unicast_address_of_its_own(self, mac, message):
        with pytest.raises(net.Refused, match=message):
            parsed(endpoint(descriptor(), "verifier", mac=mac))

    def test_refuses_a_container_name_that_is_not_a_docker_name(self):
        for name in ("", "-x", "a b", "a;b", "x" * 129):
            with pytest.raises(net.Refused, match="not a Docker name"):
                parsed(endpoint(descriptor(), "app", container=name))

    def test_refuses_everything_without_a_pool(self):
        with pytest.raises(net.Refused, match="no KOI_VERIFY_POOL"):
            net.parse_descriptor(json.dumps(descriptor()), None)

    def test_refuses_a_descriptor_past_the_size_limit(self):
        with pytest.raises(net.Refused, match="too large"):
            net.parse_descriptor(" " * (net.MAX_DESCRIPTOR_BYTES + 1), POOL)


class TestPool:
    def test_reads_the_pool_from_the_env_file(self, tmp_path):
        env = tmp_path / "env"
        env.write_text("# written by provisioning\nKOI_VERIFY_POOL=10.213.0.0/20\n")
        assert str(net.read_pool(env)) == "10.213.0.0/20"
        assert net.read_pool(tmp_path / "missing") is None
        env.write_text("OTHER=1\n")
        assert net.read_pool(env) is None

    @pytest.mark.parametrize("text", ["10.213.0.1/20", "10.0.0.0/8", "10.213.0.0/29", "fd00::/64", "pool"])
    def test_refuses_a_pool_that_is_not_an_ipv4_network_between_16_and_28_bits(self, text):
        with pytest.raises(net.Refused, match="KOI_VERIFY_POOL"):
            net.parse_pool(text)


class TestRules:
    """The exact permits for one run. Everything else on kv+ is denied by the base rules."""

    desc = parsed(descriptor())
    tag = f"-m comment --comment koi-run={RUN}"

    def test_before_the_helpers_start_binds_each_permit_to_the_bridge_address_and_mac(self):
        rules = net.generate_rules(self.desc, {"app": "veth0a", "recorder": None, "verifier": None}, KOI_UID)
        b = f"-i {BRIDGE} -o {BRIDGE}"
        assert joined(rules["KOI-VERIFY"]) == [
            # Recorder to the app's port, and the app's replies. The app runs, so
            # what goes to it must leave by its port.
            f"{b} -s 10.213.0.19 -d 10.213.0.18 -p tcp -m tcp --dport 8080 -m physdev --physdev-out veth0a -m mac --mac-source 02:4b:0a:d5:00:13 -m conntrack --ctstate NEW,ESTABLISHED {self.tag} -j ACCEPT",
            f"{b} -s 10.213.0.18 -d 10.213.0.19 -p tcp -m tcp --sport 8080 -m physdev --physdev-in veth0a -m mac --mac-source 02:42:0a:d5:00:12 -m conntrack --ctstate ESTABLISHED {self.tag} -j ACCEPT",
            # Verifier to the app's port.
            f"{b} -s 10.213.0.20 -d 10.213.0.18 -p tcp -m tcp --dport 8080 -m physdev --physdev-out veth0a -m mac --mac-source 02:4b:0a:d5:00:14 -m conntrack --ctstate NEW,ESTABLISHED {self.tag} -j ACCEPT",
            f"{b} -s 10.213.0.18 -d 10.213.0.20 -p tcp -m tcp --sport 8080 -m physdev --physdev-in veth0a -m mac --mac-source 02:42:0a:d5:00:12 -m conntrack --ctstate ESTABLISHED {self.tag} -j ACCEPT",
            # Verifier to the recorder's Playwright port.
            f"{b} -s 10.213.0.20 -d 10.213.0.19 -p tcp -m tcp --dport 4317 -m mac --mac-source 02:4b:0a:d5:00:14 -m conntrack --ctstate NEW,ESTABLISHED {self.tag} -j ACCEPT",
            f"{b} -s 10.213.0.19 -d 10.213.0.20 -p tcp -m tcp --sport 4317 -m mac --mac-source 02:4b:0a:d5:00:13 -m conntrack --ctstate ESTABLISHED {self.tag} -j ACCEPT",
        ]
        # The host reaches the recorder's control port; only replies come back in.
        assert joined(rules["KOI-VERIFY-IN"]) == [
            f"-i {BRIDGE} -s 10.213.0.19 -p tcp -m tcp --sport 4318 -m mac --mac-source 02:4b:0a:d5:00:13 -m conntrack --ctstate ESTABLISHED {self.tag} -j ACCEPT",
        ]
        assert joined(rules["KOI-VERIFY-OUT"]) == [
            f"-o {BRIDGE} -d 10.213.0.19 -p tcp -m tcp --dport 4318 -m owner --uid-owner {KOI_UID} -m conntrack --ctstate NEW {self.tag} -j ACCEPT",
            f"-o {BRIDGE} -d 10.213.0.19 -p tcp -m tcp --dport 4318 -m conntrack --ctstate ESTABLISHED {self.tag} -j ACCEPT",
        ]

    def test_once_the_helpers_run_binds_each_permit_to_its_bridge_port_too(self):
        rules = net.generate_rules(self.desc, {"app": "veth0a", "recorder": "veth0r", "verifier": "veth0v"}, KOI_UID)
        text = joined(rules["KOI-VERIFY"])
        assert text[0].count("-m physdev --physdev-in veth0r --physdev-out veth0a -m mac --mac-source 02:4b:0a:d5:00:13") == 1
        assert text[2].count("-m physdev --physdev-in veth0v --physdev-out veth0a -m mac --mac-source 02:4b:0a:d5:00:14") == 1
        assert all("--physdev-in" in rule for rule in text)
        assert "--physdev-in veth0r" in joined(rules["KOI-VERIFY-IN"])[0]

    def test_a_permit_between_containers_names_the_port_each_packet_must_leave_by(self):
        """A container that answers ARP for the recorder's address gets the verifier's packets for the recorder sent to its MAC; the bridge forwards them to its port, and only --physdev-out keeps the permit from passing them."""
        ports = {"app": "veth0a", "recorder": "veth0r", "verifier": "veth0v"}
        rules = net.generate_rules(self.desc, ports, KOI_UID)
        ip_role = {"10.213.0.18": "app", "10.213.0.19": "recorder", "10.213.0.20": "verifier"}
        for rule in rules["KOI-VERIFY"]:
            src, dst = ip_role[rule[rule.index("-s") + 1]], ip_role[rule[rule.index("-d") + 1]]
            assert rule[rule.index("--physdev-in") + 1] == ports[src]
            assert rule[rule.index("--physdev-out") + 1] == ports[dst]
        # The host's own traffic has no bridge port to name on the way out, and
        # the replies it takes in arrive at the host, not at a port.
        assert not any("--physdev-out" in r for chain in ("KOI-VERIFY-IN", "KOI-VERIFY-OUT") for r in rules[chain])
        # A port that is not known yet is left out, never guessed.
        partial = net.generate_rules(self.desc, {"app": "veth0a", "recorder": "veth0r", "verifier": None}, KOI_UID)
        to_verifier = [r for r in partial["KOI-VERIFY"] if r[r.index("-d") + 1] == "10.213.0.20"]
        assert to_verifier and not any("--physdev-out" in r for r in to_verifier)

    def test_permits_nothing_else(self):
        rules = net.generate_rules(self.desc, {}, KOI_UID)
        every = [rule for chain in rules.values() for rule in chain]
        for rule in every:
            assert rule[-1] == "ACCEPT"
            assert "tcp" in rule
            assert "conntrack" in rule
        # The app never opens a connection, and the host never reaches 4317.
        opening = [" ".join(r) for r in every if "NEW" in r[r.index("--ctstate") + 1]]
        assert not any("-s 10.213.0.18 " in r for r in opening)
        ports = sorted({r[r.index("--dport") + 1] for r in every if "--dport" in r})
        assert ports == ["4317", "4318", "8080"]
        assert not any("--dport 4317" in r for r in joined(rules["KOI-VERIFY-OUT"]))
        assert not any("--dport 4318" in r for r in joined(rules["KOI-VERIFY"]))

    def test_installs_from_the_top_of_each_chain_in_listed_order(self):
        commands = net.insert_commands(net.generate_rules(self.desc, {}, KOI_UID))
        assert [c[:6] for c in commands] == [
            ["iptables", "-w", "5", "-I", "KOI-VERIFY", "1"],
            ["iptables", "-w", "5", "-I", "KOI-VERIFY", "2"],
            ["iptables", "-w", "5", "-I", "KOI-VERIFY", "3"],
            ["iptables", "-w", "5", "-I", "KOI-VERIFY", "4"],
            ["iptables", "-w", "5", "-I", "KOI-VERIFY", "5"],
            ["iptables", "-w", "5", "-I", "KOI-VERIFY", "6"],
            ["iptables", "-w", "5", "-I", "KOI-VERIFY-IN", "1"],
            ["iptables", "-w", "5", "-I", "KOI-VERIFY-OUT", "1"],
            ["iptables", "-w", "5", "-I", "KOI-VERIFY-OUT", "2"],
        ]


class TestListing:
    """Listings are read as iptables prints them, never compared as text."""

    def test_the_default_suffix_is_recognised_in_the_order_iptables_prints_it(self):
        rules = net.parse_listing(LISTING_FORWARD)
        assert len(rules) == 14
        assert [r.canonical for r in rules[-8:]] == [net.canonical(b) for b in net.BASE_FORWARD]
        # Printed with -d before -i, the rule is not the text the helper wrote.
        assert rules[-5].tokens != net.BASE_FORWARD[3]
        assert rules[-5].canonical == net.canonical(net.BASE_FORWARD[3])
        for text, base in ((LISTING_INPUT_CHAIN, net.BASE_INPUT), (LISTING_OUTPUT_CHAIN, net.BASE_OUTPUT)):
            assert [r.canonical for r in net.parse_listing(text)[-len(base):]] == [net.canonical(b) for b in base]

    def test_a_permit_as_printed_is_the_permit_as_written(self):
        """Masks, upper case MACs, the numeric uid, -m tcp and the quoted comment all fold onto the generated rule."""
        generated = installed(descriptor(), {"app": "vethapp", "recorder": "vethrecorder", "verifier": None})
        for text, chain in ((LISTING_FORWARD, "KOI-VERIFY"), (LISTING_INPUT_CHAIN, "KOI-VERIFY-IN"), (LISTING_OUTPUT_CHAIN, "KOI-VERIFY-OUT")):
            printed = [r for r in net.parse_listing(text) if r.run == RUN]
            assert [r.canonical for r in printed] == [net.canonical(g) for g in generated[chain]]
            assert all(r.tokens != g for r, g in zip(printed, generated[chain]))

    def test_a_quoted_comment_names_the_run(self):
        rules = net.parse_listing(LISTING_FORWARD)
        assert [r.run for r in rules] == [RUN] * 6 + [None] * 8
        assert net.parse_listing(f'-A X -m comment --comment "koi-run={OTHER}" -j ACCEPT')[0].run == OTHER
        assert net.parse_listing(f"-A X -m comment --comment koi-run={OTHER} -j ACCEPT")[0].run == OTHER
        # Not a run id, not a run's rule.
        assert net.parse_listing('-A X -m comment --comment "koi-run=Not A Run" -j ACCEPT')[0].run is None
        assert net.parse_listing('-A X -m comment --comment "other" -j ACCEPT')[0].run is None

    def test_an_address_printed_with_its_mask_still_gives_the_subnet(self):
        rule = net.parse_listing(LISTING_FORWARD)[0]
        assert rule.options("-s") == ["10.213.0.19/32"]
        assert net.rule_subnets(rule) == {ipaddress.ip_network("10.213.0.16/28")}
        assert net.rule_subnets(net.parse_listing(LISTING_OUTPUT_CHAIN)[0]) == {ipaddress.ip_network("10.213.0.16/28")}

    def test_canonical_form_ignores_order_mask_case_and_quoting_but_not_meaning(self):
        a = net.canonical("-i kv+ -d 224.0.0.0/4 -j DROP".split())
        assert a == net.canonical("-d 224.0.0.0/4 -i kv+ -j DROP".split())
        assert net.canonical("-s 10.213.0.19 -j ACCEPT".split()) == net.canonical("-s 10.213.0.19/32 -j ACCEPT".split())
        assert net.canonical("-m mac --mac-source 02:4b:0a:d5:00:13".split()) == net.canonical("-m mac --mac-source 02:4B:0A:D5:00:13".split())
        assert net.canonical("-p tcp --dport 53 -j DROP".split()) == net.canonical("-p tcp -m tcp --dport 53 -j DROP".split())
        assert net.canonical("-m conntrack --ctstate NEW,ESTABLISHED".split()) == net.canonical("-m conntrack --ctstate ESTABLISHED,NEW".split())
        assert net.canonical("-i kv+ -j DROP".split()) != net.canonical("-o kv+ -j DROP".split())
        assert net.canonical("-i kv+ -j DROP".split()) != net.canonical("! -i kv+ -j DROP".split())
        assert net.canonical("-p tcp -m tcp --dport 53 -j DROP".split()) != net.canonical("-p tcp -m tcp --dport 54 -j DROP".split())

    def test_delete_commands_take_only_the_runs_rules_last_first(self):
        commands = net.delete_commands(LISTING_FORWARD, RUN)
        assert len(commands) == 6
        assert commands[0][:5] == ["iptables", "-w", "5", "-D", "KOI-VERIFY"]
        # The last printed permit goes first, its tokens as printed, the comment unquoted.
        assert commands[0][5:] == net.parse_listing(LISTING_FORWARD)[5].tokens
        assert commands[0][-4:] == ["--comment", f"koi-run={RUN}", "-j", "ACCEPT"]
        assert net.delete_commands(LISTING_FORWARD, OTHER) == []

    def test_a_value_is_read_by_the_count_its_option_takes_not_by_its_look(self):
        rules = net.parse_listing(LISTING_INPUT_ODD)
        assert [r.unparsed for r in rules] == [None] * 5
        assert [r.target for r in rules] == ["ACCEPT"] * 4 + ["KOI-VERIFY-IN"]
        assert [r.option("--comment") for r in rules[:3]] == ODD_COMMENTS
        assert [r.option("-i") for r in rules[:3]] == ["kv+"] * 3
        # The text for a message quotes a value the shell would need quoted, and leaves a negation bare.
        assert rules[0].text == "-i kv+ -m comment --comment '!' -j ACCEPT"
        assert rules[2].text == "-i kv+ -m comment --comment -j -j ACCEPT"
        negated = rules[3]
        assert ("! -i", ("kv+",)) in negated.groups
        assert negated.option("-i") is None
        assert negated.canonical != net.canonical("-i kv+ -j ACCEPT".split())
        assert negated.text == "! -i kv+ -j ACCEPT"
        # Deleting by the parsed tokens hands iptables the comment as one argument again.
        assert net.delete_command(rules[0])[-6:] == ["-m", "comment", "--comment", "!", "-j", "ACCEPT"]

    def test_an_option_it_does_not_know_leaves_the_rule_unparsed_but_still_read_as_far_as_it_goes(self):
        for tokens, reason in (
            ("-i kv+ -m made-up --made-up-option 3 -j DROP", "option --made-up-option is not one koi-verify-net knows"),
            ("-i kv+ ! --made-up-flag -j DROP", "option --made-up-flag is not one koi-verify-net knows"),
            ("-i kv+ stray -j DROP", "'stray' where an option was expected"),
            ("-i kv+ ! ! -j DROP", "'!' where an option was expected"),
            ("-j DROP -i", "option -i is missing a value"),
            ("-j DROP !", "a negation mark with no option after it"),
        ):
            rule = net.Rule(tokens.split())
            assert rule.unparsed == reason, tokens
            # The target is still a guess worth having: provision deletes a jump by it.
            assert rule.target == "DROP", tokens
        rule = net.Rule("-i kv+ -m made-up --made-up-option 3 -j DROP".split())
        assert rule.text == "-i kv+ -m made-up --made-up-option 3 -j DROP"
        assert ("--made-up-option", ("3",)) in rule.groups
        assert all(net.Rule(r).unparsed is None for spec in net.CHAINS for r in spec["base"])
        assert all(r.unparsed is None for r in net.parse_listing(LISTING_FORWARD + LISTING_INPUT + LISTING_DOCKER_USER))

    def test_every_option_the_parser_knows_is_an_alias_target_or_a_short_spelling(self):
        for long, short in net.ALIASES.items():
            assert short in net.OPTION_ARITY, long
            assert long not in net.OPTION_ARITY, long
        assert all(arity in (0, 1, 2) for arity in net.OPTION_ARITY.values())

    def test_the_fake_prints_what_the_box_prints(self, box):
        """The stand-in's listings are the fixtures above, so every test here runs against the real format."""
        desc = descriptor()
        box.docker(desc, running=("app", "recorder"))
        box.apply(desc)
        assert box.listing("KOI-VERIFY") == LISTING_FORWARD
        assert box.listing("KOI-VERIFY-IN") == LISTING_INPUT_CHAIN
        assert box.listing("KOI-VERIFY-OUT") == LISTING_OUTPUT_CHAIN
        assert box.listing("DOCKER-USER") == LISTING_DOCKER_USER
        assert box.listing("INPUT") == LISTING_INPUT
        # The odd comments and the negation too: the stand-in takes values by count, as iptables does.
        for comment in reversed(ODD_COMMENTS):
            box.fw.command("iptables", ["-I", "INPUT", "1", "-i", "kv+", "-m", "comment", "--comment", comment, "-j", "ACCEPT"])
        box.fw.command("iptables", ["-I", "INPUT", "4", "!", "-i", "kv+", "-j", "ACCEPT"])
        assert box.listing("INPUT").startswith(LISTING_INPUT_ODD)
        # And a listing of the whole table is every header, then every rule.
        lines = box.fw.whole("iptables").splitlines()
        headers = [line for line in lines if line.startswith(("-P ", "-N "))]
        assert lines[: len(headers)] == headers
        assert "-N KOI-VERIFY-OUT" in headers
        assert [line for line in lines if line.startswith("-A INPUT ")] == LISTING_INPUT_ODD.splitlines()[1:] + LISTING_INPUT.splitlines()[2:]


class TestOverlap:
    subnet = ipaddress.ip_network("10.213.0.16/28")

    def test_a_subnet_beside_every_route_is_free(self):
        assert net.overlapping(self.subnet, ROUTES, BRIDGE) is None

    def test_the_runs_own_bridge_does_not_count(self):
        own = ROUTES + [{"dst": "10.213.0.16/28", "dev": BRIDGE}]
        assert net.overlapping(self.subnet, own, BRIDGE) is None

    def test_another_bridge_or_the_box_network_on_the_same_addresses_does(self):
        other = ROUTES + [{"dst": "10.213.0.16/28", "dev": "kvbbbbbbbbbbbb"}]
        assert net.overlapping(self.subnet, other, BRIDGE) == "10.213.0.16/28"
        wide = ROUTES + [{"dst": "10.213.0.0/16", "dev": "ens6"}]
        assert net.overlapping(self.subnet, wide, BRIDGE) == "10.213.0.0/16"


class TestPeerPort:
    inside = [
        {"ifindex": 1, "ifname": "lo", "address": "00:00:00:00:00:00"},
        {"ifindex": 40, "link_index": 41, "ifname": "eth0", "address": "02:42:ac:12:00:03"},
        {"ifindex": 44, "link_index": 45, "ifname": "eth1", "address": "02:4b:0a:d5:00:13"},
    ]
    outside = [
        {"ifindex": 41, "link_index": 40, "ifname": "veth1111", "master": "koi-previews0"},
        {"ifindex": 45, "link_index": 44, "ifname": "veth2222", "master": BRIDGE},
    ]

    def test_finds_the_host_side_of_the_interface_with_the_expected_mac_on_the_expected_bridge(self):
        assert net.peer_port(self.inside, self.outside, "02:4b:0a:d5:00:13", BRIDGE) == "veth2222"

    def test_refuses_an_interface_on_another_bridge_or_a_mac_that_is_not_there(self):
        with pytest.raises(net.Refused, match="is on koi-previews0, not"):
            net.peer_port(self.inside, self.outside, "02:42:ac:12:00:03", BRIDGE)
        with pytest.raises(net.Refused, match="0 interfaces with mac"):
            net.peer_port(self.inside, self.outside, "02:4b:0a:d5:00:14", BRIDGE)
        with pytest.raises(net.Refused, match="no host interface has index"):
            net.peer_port(self.inside, self.outside[:1], "02:4b:0a:d5:00:13", BRIDGE)
        with pytest.raises(net.Refused, match="not one end of a veth pair"):
            net.peer_port([{"ifindex": 2, "address": "02:4b:0a:d5:00:13"}], self.outside, "02:4b:0a:d5:00:13", BRIDGE)


# --- The commands, against the stand-in for the box ---------------------------------


class TestProvision:
    def test_a_fresh_box_gets_the_chains_their_defaults_and_the_jumps_in_front(self, bare):
        result = bare.provision()
        assert bare.clean()
        assert bare.rules("DOCKER-USER")[0] == ["-j", "KOI-VERIFY"]
        assert bare.rules("INPUT")[0] == ["-i", "kv+", "-j", "KOI-VERIFY-IN"]
        assert bare.rules("OUTPUT")[0] == ["-o", "kv+", "-j", "KOI-VERIFY-OUT"]
        assert bare.rules("INPUT", "ip6tables")[0] == ["-i", "kv+", "-j", "DROP"]
        assert bare.rules("FORWARD", "ip6tables")[:2] == [["-o", "kv+", "-j", "DROP"], ["-i", "kv+", "-j", "DROP"]]
        assert bare.rules("OUTPUT", "ip6tables")[0] == ["-o", "kv+", "-j", "DROP"]
        # What koi-firewall put there stays, below.
        assert bare.rules("DOCKER-USER")[1:] == [["-d", "169.254.169.254/32", "-j", "DROP"], ["-j", "RETURN"]]
        assert len(bare.rules("INPUT")) == 4
        assert result["ipv4"] == {"chains": True, "jump": True, "defaults": True, "permits": True, "problems": []}
        assert result["ipv6"] == {"defaults": True, "problems": []}
        assert result["changed"] == [
            "created chain KOI-VERIFY",
            "chain DOCKER-USER: inserted -j KOI-VERIFY first",
            "created chain KOI-VERIFY-IN",
            "chain INPUT: inserted -i kv+ -j KOI-VERIFY-IN first",
            "created chain KOI-VERIFY-OUT",
            "chain OUTPUT: inserted -o kv+ -j KOI-VERIFY-OUT first",
            "ip6tables INPUT: inserted -i kv+ -j DROP first",
            "ip6tables FORWARD: inserted -i kv+ -j DROP first",
            "ip6tables FORWARD: inserted -o kv+ -j DROP first",
            "ip6tables OUTPUT: inserted -o kv+ -j DROP first",
            "created ebtables chain KOI-VERIFY-L2",
            "ebtables FORWARD: inserted --logical-in kv+ -j KOI-VERIFY-L2 first",
        ]
        assert bare.l2.ebtables["FORWARD"] == [["--logical-in", "kv+", "-j", "KOI-VERIFY-L2"]]
        assert bare.l2.ebtables["KOI-VERIFY-L2"] == [["-p", "IPv4", "-j", "RETURN"], ["-p", "ARP", "-j", "RETURN"], ["-j", "DROP"]]
        assert result["bridge"] == {"guard": True, "pins": True, "problems": []}
        assert bare.attest()["ipv4"]["problems"] == []

    def test_a_second_run_changes_nothing(self, box):
        result = box.provision()
        assert result["changed"] == []
        assert box.changes() == []

    def test_keeps_a_runs_permits_while_it_rebuilds_a_chain_whose_defaults_differ(self, box):
        desc = descriptor()
        box.docker(desc, running=("app",))
        box.apply(desc)
        # An older generation of defaults: one rule short, one a REJECT.
        rules = box.rules("KOI-VERIFY")
        del rules[-3]
        rules[-1] = render("-o kv+ -j REJECT".split())
        permits = [r for r in rules if "--comment" in r]
        assert len(permits) == 9 - 3
        box.calls.clear()
        box.fw.watching = True
        result = box.provision()
        assert box.fw.unconfined_after == []
        assert box.fw.checks > 10
        assert box.rules("KOI-VERIFY") == permits + [render(r) for r in net.BASE_FORWARD]
        assert "rebuilt chain KOI-VERIFY with 6 run permits above its defaults" in result["changed"]
        assert result["ipv4"]["permits"] is True
        assert result["ipv4"]["problems"] == []
        assert "KOI-VERIFY-NEW" not in box.fw.tables["iptables"]
        # The new chain is reached before the old one goes.
        changes = box.changes()
        order = [
            "iptables -w 5 -N KOI-VERIFY-NEW",
            f"iptables -w 5 -A KOI-VERIFY-NEW {' '.join(permits[0])}",
            "iptables -w 5 -A KOI-VERIFY-NEW -i kv+ -m conntrack --ctstate INVALID -j DROP",
            "iptables -w 5 -I DOCKER-USER 1 -j KOI-VERIFY-NEW",
            "iptables -w 5 -D DOCKER-USER -j KOI-VERIFY",
            "iptables -w 5 -F KOI-VERIFY",
            "iptables -w 5 -X KOI-VERIFY",
            "iptables -w 5 -E KOI-VERIFY-NEW KOI-VERIFY",
        ]
        positions = [changes.index(c) for c in order]
        assert positions == sorted(positions)
        # The other two chains were as wanted and were left alone.
        assert not any("KOI-VERIFY-IN-NEW" in c or "KOI-VERIFY-OUT-NEW" in c for c in changes)
        assert box.state_file().exists()

    def test_the_old_inline_layout_of_an_earlier_provisioning_is_already_the_wanted_one(self, bare):
        """A chain cloud-init appended by hand, permits above, is left as it is."""
        for spec in net.CHAINS:
            bare.fw.command("iptables", ["-N", spec["chain"]])
            for rule in spec["base"]:
                bare.fw.command("iptables", ["-A", spec["chain"], *rule])
            bare.fw.command("iptables", ["-I", spec["parent"], *spec["match"], "-j", spec["chain"]])
        for parent, rule, _ in net.BASE_IPV6:
            bare.fw.command("ip6tables", ["-I", parent, *rule])
        permit = f"-i {BRIDGE} -o {BRIDGE} -s 10.213.0.19 -d 10.213.0.18 -p tcp --dport 8080 -m comment --comment koi-run={RUN} -j ACCEPT"
        bare.fw.command("iptables", ["-I", "KOI-VERIFY", "1", *permit.split()])
        result = bare.provision()
        assert [c for c in result["changed"] if "ebtables" not in c] == []
        assert bare.rules("KOI-VERIFY")[0] == render(permit.split())

    def test_finishes_a_swap_an_earlier_run_left_half_done(self, box):
        permit = render(f"-i {BRIDGE} -s 10.213.0.19 -m comment --comment koi-run={RUN} -j ACCEPT".split())
        # The new chain is built and reached; the old jump and chain are still there.
        box.fw.tables["iptables"]["KOI-VERIFY-NEW"] = [permit] + [render(r) for r in net.BASE_FORWARD]
        box.fw.tables["iptables"]["DOCKER-USER"].insert(0, ["-j", "KOI-VERIFY-NEW"])
        box.fw.tables["iptables"]["KOI-VERIFY"] = [permit, render("-i kv+ -j DROP".split())]
        box.fw.watching = True
        result = box.provision()
        assert box.fw.unconfined_after == []
        assert "replaced chain KOI-VERIFY" in result["changed"]
        assert "KOI-VERIFY-NEW" not in box.fw.tables["iptables"]
        assert box.rules("KOI-VERIFY") == [permit] + [render(r) for r in net.BASE_FORWARD]
        assert [r for r in box.rules("DOCKER-USER") if r[0] == "-j" and r[1].startswith("KOI")] == [["-j", "KOI-VERIFY"]]
        assert box.rules("DOCKER-USER")[0] == ["-j", "KOI-VERIFY"]

    def test_removes_a_new_chain_nothing_reaches(self, box):
        box.fw.tables["iptables"]["KOI-VERIFY-IN-NEW"] = [render("-j DROP".split())]
        result = box.provision()
        assert result["changed"] == ["removed the unfinished chain KOI-VERIFY-IN-NEW"]
        assert "KOI-VERIFY-IN-NEW" not in box.fw.tables["iptables"]
        assert box.changes() == ["iptables -w 5 -F KOI-VERIFY-IN-NEW", "iptables -w 5 -X KOI-VERIFY-IN-NEW"]

    def test_moves_a_jump_that_something_got_in_front_of_without_a_gap(self, box):
        # Another rule took the top of DOCKER-USER. Confinement holds (it is
        # a deny), but attest wants the jump first, and the move leaves no gap.
        box.fw.command("iptables", ["-I", "DOCKER-USER", "1", "-d", "10.0.0.0/8", "-j", "DROP"])
        assert box.attest()["ipv4"]["jump"] is False
        box.calls.clear()
        box.fw.watching = True
        result = box.provision()
        assert box.fw.unconfined_after == []
        assert result["changed"] == [
            "chain DOCKER-USER: inserted -j KOI-VERIFY first",
            "chain DOCKER-USER: removed a later copy of -j KOI-VERIFY",
        ]
        assert box.changes() == ["iptables -w 5 -I DOCKER-USER 1 -j KOI-VERIFY", "iptables -w 5 -D DOCKER-USER 3"]
        assert box.rules("DOCKER-USER")[:2] == [["-j", "KOI-VERIFY"], ["-d", "10.0.0.0/8", "-j", "DROP"]]
        assert result["ipv4"]["jump"] is True

    def test_puts_the_input_jump_back_in_front_of_an_accept_for_kv(self, box):
        box.fw.command("iptables", ["-I", "INPUT", "1", "-i", "kv+", "-j", "ACCEPT"])
        assert box.attest()["ipv4"]["jump"] is False
        box.calls.clear()
        result = box.provision()
        assert result["changed"] == [
            "chain INPUT: inserted -i kv+ -j KOI-VERIFY-IN first",
            "chain INPUT: removed a later copy of -i kv+ -j KOI-VERIFY-IN",
        ]
        assert box.changes() == ["iptables -w 5 -I INPUT 1 -i kv+ -j KOI-VERIFY-IN", "iptables -w 5 -D INPUT 3"]
        assert box.rules("INPUT")[:2] == [["-i", "kv+", "-j", "KOI-VERIFY-IN"], ["-i", "kv+", "-j", "ACCEPT"]]
        assert result["ipv4"]["jump"] is True
        assert box.fw.confined()

    def test_puts_an_ipv6_deny_back_in_front_of_an_accept(self, box):
        box.fw.command("ip6tables", ["-I", "OUTPUT", "1", "-j", "ACCEPT"])
        assert box.attest()["ipv6"]["defaults"] is False
        result = box.provision()
        assert result["changed"] == [
            "ip6tables OUTPUT: inserted -o kv+ -j DROP first",
            "ip6tables OUTPUT: removed a later copy of -o kv+ -j DROP",
        ]
        assert box.rules("OUTPUT", "ip6tables") == [["-o", "kv+", "-j", "DROP"], ["-j", "ACCEPT"]]
        assert result["ipv6"]["defaults"] is True

    def test_refuses_without_docker_user(self, bare):
        del bare.fw.tables["iptables"]["DOCKER-USER"]
        bare.fw.tables["iptables"]["FORWARD"] = []
        with pytest.raises(net.Refused, match="chain DOCKER-USER does not exist; Docker makes it"):
            bare.provision()
        assert bare.changes() == []


class TestApply:
    def test_installs_the_runs_generation_above_the_defaults_and_records_it(self, box):
        desc = descriptor()
        box.docker(desc, running=("app",))
        result = box.apply(desc)
        ports = {"app": "vethapp", "recorder": None, "verifier": None}
        assert result == {"runId": RUN, "rules": 9, "ports": ports}
        rules = installed(desc, ports)
        # The app's MAC is pinned to its port before the first permit goes in.
        assert box.changes() == [
            "bridge fdb replace 02:42:0a:d5:00:12 dev vethapp master static sticky",
            *[" ".join(c) for c in net.insert_commands(rules)],
        ]
        for chain, chain_rules in rules.items():
            assert box.rules(chain) == [render(r) for r in chain_rules] + box.rules(chain)[len(chain_rules):]
        report = box.attest()
        assert report["ipv4"] == {"chains": True, "jump": True, "defaults": True, "permits": True, "problems": []}
        assert report["runs"] == [RUN]
        # koid holds a runner back until the port it needs is one here.
        assert report["ports"] == {RUN: ports}
        state = json.loads(box.state_file().read_text())
        assert (state["subnet"], state["bridge"], state["ports"], state["uid"]) == ("10.213.0.16/28", BRIDGE, ports, KOI_UID)
        assert oct(box.state_file().stat().st_mode & 0o777) == "0o600"

    def test_writes_the_state_before_the_first_rule(self, box):
        desc = descriptor()
        box.docker(desc)
        box.apply(desc)
        assert box.state_at_first_insert is True

    def test_binds_the_bridge_ports_once_every_container_runs(self, box):
        desc = descriptor()
        box.docker(desc, running=net.ROLES)
        result = box.apply(desc)
        assert result["ports"] == {"app": "vethapp", "recorder": "vethrecorder", "verifier": "vethverifier"}
        assert all("--physdev-in" in c for c in box.changes() if c.startswith("iptables") and "KOI-VERIFY-OUT" not in c)
        assert any(f"nsenter --net=/var/run/docker/netns/{r} -- ip -j link show" in box.calls for r in net.ROLES)

    def test_a_second_apply_replaces_the_runs_rules(self, box):
        desc = descriptor()
        box.docker(desc)
        box.apply(desc)
        first = [r for r in box.rules("KOI-VERIFY") if "--comment" in r]
        box.docker(desc, running=("app",))
        box.calls.clear()
        box.apply(desc)
        deletes = [c for c in box.changes() if " -D " in c]
        inserts = [c for c in box.changes() if " -I " in c]
        assert len(deletes) == 9
        assert len(inserts) == 9
        assert box.calls.index(deletes[-1]) < box.calls.index(inserts[0])
        # The deletes name the rules as the listing printed them, last first.
        forward = [c for c in deletes if c.startswith("iptables -w 5 -D KOI-VERIFY ")]
        assert forward[0].startswith(f"iptables -w 5 -D KOI-VERIFY -s 10.213.0.19/32 -d 10.213.0.20/32 -i {BRIDGE}")
        # One generation: the rules that changed (the app's replies now name
        # its bridge port) replaced, the rest the same, none twice.
        permits = [r for r in box.rules("KOI-VERIFY") if "--comment" in r]
        assert len(permits) == 6
        # In the app's two replies (--physdev-in) and the two permits to it (--physdev-out).
        assert len([r for r in permits if "vethapp" in r]) == 4
        assert len([r for r in first if "vethapp" in r]) == 0
        assert box.attest()["ipv4"]["permits"] is True
        # The state still described the old generation while it went, and
        # describes the new one before its first rule went in.
        assert box.state_at_last_delete["ports"] == {"app": None, "recorder": None, "verifier": None}
        state = json.loads(box.state_file().read_text())
        assert state["ports"] == {"app": "vethapp", "recorder": None, "verifier": None}

    # Where a second apply can die: before each of the nine deletes of the
    # old generation, at the state write, before the app's pin, and before
    # each of the nine inserts of the new one.
    CRASH_POINTS = [
        *[(f"before delete {i + 1}", i) for i in range(9)],
        ("at the state write", "state"),
        ("before the pin", 9),
        *[(f"before insert {i + 1}", 10 + i) for i in range(9)],
    ]

    @pytest.mark.parametrize("point", [p for _, p in CRASH_POINTS], ids=[name for name, _ in CRASH_POINTS])
    def test_a_second_apply_that_dies_anywhere_leaves_only_rules_its_state_describes(self, box, monkeypatch, point):
        """attest compares the installed permits with the state.

        A crash must never leave them apart: the host would fail the permit
        check, and every apply and every capability check after it, until
        someone fixed it by hand.
        """
        desc = descriptor()
        box.docker(desc)
        box.apply(desc)
        box.docker(desc, running=("app",))
        write_state = net.write_state
        if point == "state":

            def die(*args):
                raise Crash("write_state")

            monkeypatch.setattr(net, "write_state", die)
        else:
            box.crash_before = point
        box.fw.watching = True
        with pytest.raises(Crash) as died:
            box.apply(desc)
        box.fw.watching = False
        assert box.fw.unconfined_after == []
        if point != "state":
            assert (" -D " if point < 9 else "bridge fdb replace " if point == 9 else " -I ") in str(died.value)
        # The state still holds the subnet, and describes every rule of the
        # run that is installed.
        state = json.loads(box.state_file().read_text())
        assert state["subnet"] == "10.213.0.16/28"
        assert box.attest()["ipv4"] == {"chains": True, "jump": True, "defaults": True, "permits": True, "problems": []}
        # So the next apply is not refused and leaves one generation, and a
        # revoke leaves nothing.
        box.crash_before = None
        monkeypatch.setattr(net, "write_state", write_state)
        assert box.apply(desc)["rules"] == 9
        permits = [r for r in box.rules("KOI-VERIFY") if "--comment" in r]
        assert len(permits) == 6
        # In the app's two replies (--physdev-in) and the two permits to it (--physdev-out).
        assert len([r for r in permits if "vethapp" in r]) == 4
        assert box.attest()["ipv4"]["permits"] is True
        assert box.revoke(RUN) == {"runId": RUN, "removed": 9, "flushed": ["10.213.0.16/28"]}
        assert box.clean()
        assert not box.state_file().exists()

    def test_finishes_a_swap_an_interrupted_provision_left_before_it_checks_the_host(self, box):
        desc = descriptor()
        box.docker(desc)
        box.apply(desc)
        chains = box.fw.tables["iptables"]
        # Provision stopped right after the jump moved to the staged chain.
        chains["KOI-VERIFY-NEW"] = [list(r) for r in chains["KOI-VERIFY"]]
        chains["DOCKER-USER"].insert(0, ["-j", "KOI-VERIFY-NEW"])
        assert box.attest()["ipv4"]["jump"] is False
        box.docker(desc, running=("app",))
        box.calls.clear()
        assert box.apply(desc)["rules"] == 9
        assert box.changes()[:4] == [
            "iptables -w 5 -D DOCKER-USER -j KOI-VERIFY",
            "iptables -w 5 -F KOI-VERIFY",
            "iptables -w 5 -X KOI-VERIFY",
            "iptables -w 5 -E KOI-VERIFY-NEW KOI-VERIFY",
        ]
        assert "KOI-VERIFY-NEW" not in chains
        assert box.rules("DOCKER-USER")[0] == ["-j", "KOI-VERIFY"]
        permits = [r for r in box.rules("KOI-VERIFY") if f"koi-run={RUN}" in r]
        assert len(permits) == 6
        # In the app's two replies (--physdev-in) and the two permits to it (--physdev-out).
        assert len([r for r in permits if "vethapp" in r]) == 4
        assert box.attest()["ipv4"] == {"chains": True, "jump": True, "defaults": True, "permits": True, "problems": []}

    def test_leaves_another_runs_rules_alone(self, box):
        other = other_descriptor()
        box.docker(other)
        box.apply(other)
        desc = descriptor()
        box.docker(desc)
        box.calls.clear()
        box.apply(desc)
        assert not any(" -D " in c for c in box.changes())
        assert len([r for r in box.rules("KOI-VERIFY") if f"koi-run={OTHER}" in r]) == 6
        assert sorted(box.attest()["runs"]) == sorted([RUN, OTHER])
        assert box.attest()["ipv4"]["permits"] is True

    def test_removes_what_it_installed_when_an_insert_fails_and_keeps_the_state_for_revoke(self, box):
        desc = descriptor()
        box.docker(desc)
        commands = net.insert_commands(installed(desc, {r: None for r in net.ROLES}))
        box.failing[" ".join(commands[3])] = "iptables -w 5 -I exited 2: No chain/target/match by that name"
        with pytest.raises(net.Failed, match="No chain/target/match"):
            box.apply(desc)
        assert len([c for c in box.changes() if " -D " in c]) == 3
        assert box.clean()
        # The state stays: a flow of an earlier generation may still be tracked.
        assert box.state_file().exists()
        box.calls.clear()
        assert box.revoke(RUN) == {"runId": RUN, "removed": 0, "flushed": ["10.213.0.16/28"]}
        assert not box.state_file().exists()

    def test_refuses_a_host_that_is_not_as_provisioning_leaves_it(self, box):
        desc = descriptor()
        box.docker(desc)
        box.fw.tables["iptables"]["KOI-VERIFY-OUT"] = []
        with pytest.raises(net.Refused, match="not as provisioning leaves it.*KOI-VERIFY-OUT does not end"):
            box.apply(desc)
        box.provision()
        box.fw.command("iptables", ["-I", "KOI-VERIFY", "1", "-i", "kv+", "-j", "ACCEPT"])
        with pytest.raises(net.Refused, match="not a run permit above its defaults: -i kv\\+ -j ACCEPT"):
            box.apply(desc)
        box.fw.command("iptables", ["-D", "KOI-VERIFY", "-i", "kv+", "-j", "ACCEPT"])
        box.fw.command("iptables", ["-I", "DOCKER-USER", "1", "-j", "RETURN"])
        with pytest.raises(net.Refused, match="DOCKER-USER does not start with -j KOI-VERIFY"):
            box.apply(desc)
        assert not any(c.startswith("iptables -w 5 -I KOI-VERIFY") for c in box.calls)

    def test_refuses_a_subnet_another_run_holds_or_a_host_route_covers(self, box):
        desc = descriptor()
        box.docker(desc)
        box.state.mkdir()
        (box.state / f"{OTHER}.json").write_text(json.dumps({"subnet": "10.213.0.16/28", "bridge": "kvzzzzzzzzzzzz"}))
        with pytest.raises(net.Refused, match=f"overlaps run {OTHER}'s"):
            box.apply(desc)
        (box.state / f"{OTHER}.json").write_text(json.dumps({"subnet": "10.213.0.32/28", "bridge": BRIDGE}))
        with pytest.raises(net.Refused, match=f"bridge {BRIDGE} belongs to run"):
            box.apply(desc)
        (box.state / f"{OTHER}.json").unlink()
        box.answers["ip -j route show"] = json.dumps(ROUTES + [{"dst": "10.213.0.0/24", "dev": "ens6"}])
        with pytest.raises(net.Refused, match="overlaps the host route 10.213.0.0/24"):
            box.apply(desc)
        assert box.changes() == []

    def test_refuses_to_move_a_run_to_another_subnet_without_a_revoke(self, box):
        desc = descriptor()
        box.docker(desc)
        box.apply(desc)
        moved = descriptor(subnet="10.213.0.32/28")
        for role, host in (("app", 34), ("recorder", 35), ("verifier", 36)):
            moved = endpoint(moved, role, ip=f"10.213.0.{host}")
        box.docker(moved)
        with pytest.raises(net.Refused, match=f"run {RUN} already holds 10.213.0.16/28 on {BRIDGE}; revoke it first"):
            box.apply(moved)

    @pytest.mark.parametrize(
        "change, message",
        [
            ({"Internal": False}, "is not internal"),
            ({"EnableIPv6": True}, "has IPv6 enabled"),
            ({"Options": {"com.docker.network.bridge.name": BRIDGE}}, "lets its containers reach each other"),
            ({"Options": {"com.docker.network.bridge.enable_icc": "false", "com.docker.network.bridge.name": "kvffffffffffff"}}, "has bridge"),
            ({"IPAM": {"Config": [{"Subnet": "10.213.0.32/28"}]}}, "has subnets"),
            ({"Labels": {}}, "not labelled koi.run"),
        ],
    )
    def test_refuses_a_network_that_is_not_the_runs(self, box, change, message):
        desc = descriptor()
        box.docker(desc)
        key, info = box.inspected(NETWORK)
        box.answers[key] = json.dumps({**info, **change})
        with pytest.raises(net.Refused, match=message):
            box.apply(desc)
        assert box.changes() == []
        assert not box.state_file().exists()

    def test_refuses_an_app_whose_attachment_is_not_what_the_descriptor_says(self, box):
        desc = descriptor()
        box.docker(desc, running=("app",))
        key, info = box.inspected(APP)
        info["NetworkSettings"]["Networks"][NETWORK]["MacAddress"] = "02:42:0a:d5:00:99"
        box.answers[key] = json.dumps(info)
        with pytest.raises(net.Refused, match="has mac '02:42:0a:d5:00:99', not 02:42:0a:d5:00:12"):
            box.apply(desc)
        info["NetworkSettings"]["Networks"][NETWORK]["MacAddress"] = "02:42:0a:d5:00:12"
        info["Config"]["Labels"] = {"koi.role": "recorder", "koi.run": RUN}
        box.answers[key] = json.dumps(info)
        with pytest.raises(net.Refused, match="is not a preview container"):
            box.apply(desc)
        info["Config"]["Labels"] = {"koi.preview": "hello-pr-7"}
        del info["NetworkSettings"]["Networks"][NETWORK]
        box.answers[key] = json.dumps(info)
        with pytest.raises(net.Refused, match=f"is not attached to {NETWORK}"):
            box.apply(desc)
        assert box.changes() == []

    def test_checks_a_helper_that_has_not_started_on_what_it_is_configured_for(self, box):
        desc = descriptor()
        box.docker(desc, running=("app",))
        key, info = box.inspected(RECORDER)
        info["NetworkSettings"]["Networks"][NETWORK]["IPAMConfig"]["IPv4Address"] = "10.213.0.21"
        box.answers[key] = json.dumps(info)
        with pytest.raises(net.Refused, match="configured for address '10.213.0.21'"):
            box.apply(desc)
        info["NetworkSettings"]["Networks"][NETWORK]["IPAMConfig"]["IPv4Address"] = "10.213.0.19"
        info["NetworkSettings"]["Networks"][NETWORK]["MacAddress"] = "02:4b:0a:d5:00:99"
        box.answers[key] = json.dumps(info)
        with pytest.raises(net.Refused, match="configured for mac '02:4b:0a:d5:00:99'"):
            box.apply(desc)
        # Docker fills the MAC in only when it starts the container; empty is fine.
        info["NetworkSettings"]["Networks"][NETWORK]["MacAddress"] = ""
        info["Config"]["Labels"] = {"koi.role": "recorder", "koi.run": OTHER}
        box.answers[key] = json.dumps(info)
        with pytest.raises(net.Refused, match="not labelled koi.role=recorder"):
            box.apply(desc)
        assert box.changes() == []
        info["Config"]["Labels"] = {"koi.role": "recorder", "koi.run": RUN}
        box.answers[key] = json.dumps(info)
        assert box.apply(desc)["rules"] == 9

    def test_refuses_a_running_helper_whose_port_is_on_another_bridge(self, box):
        desc = descriptor()
        box.docker(desc, running=net.ROLES)
        box.links[1]["master"] = "koi-previews0"
        with pytest.raises(net.Refused, match="vethrecorder is on koi-previews0"):
            box.apply(desc)
        assert box.changes() == []


def conntrack_failure(message):
    return net.Failed(f"conntrack -D -s 10.213.0.16/28 exited 1: {message}", returncode=1, stderr=message + "\n")


class TestRevoke:
    def test_removes_the_generation_then_flushes_the_subnets_connections(self, box):
        desc = descriptor()
        box.docker(desc, running=("app", "recorder"))
        box.apply(desc)
        box.calls.clear()
        result = box.revoke(RUN)
        assert result == {"runId": RUN, "removed": 9, "flushed": ["10.213.0.16/28"]}
        changes = box.changes()
        assert len([c for c in changes if c.startswith("iptables -w 5 -D KOI-VERIFY ")]) == 6
        assert len([c for c in changes if c.startswith("iptables -w 5 -D KOI-VERIFY-IN ")]) == 1
        assert len([c for c in changes if c.startswith("iptables -w 5 -D KOI-VERIFY-OUT ")]) == 2
        assert changes[-2:] == ["conntrack -D -s 10.213.0.16/28", "conntrack -D -d 10.213.0.16/28"]
        assert box.clean()
        assert not box.state_file().exists()
        assert box.attest()["runs"] == []

    def test_takes_the_subnet_from_addresses_as_the_listing_prints_them(self, box):
        """The listing says 10.213.0.19/32; the subnet is still 10.213.0.16/28."""
        box.fw.command("iptables", ["-I", "KOI-VERIFY", "1", *f"-i {BRIDGE} -o {BRIDGE} -s 10.213.0.19 -d 10.213.0.18 -m comment --comment koi-run={RUN} -j ACCEPT".split()])
        assert box.rules("KOI-VERIFY")[0][:4] == ["-s", "10.213.0.19/32", "-d", "10.213.0.18/32"]
        assert box.revoke(RUN) == {"runId": RUN, "removed": 1, "flushed": ["10.213.0.16/28"]}
        assert box.clean()
        assert not box.state_file().exists()

    def test_without_a_state_file_records_the_subnet_before_any_rule_goes(self, box):
        box.fw.command("iptables", ["-I", "KOI-VERIFY", "1", *f"-i {BRIDGE} -o {BRIDGE} -s 10.213.0.19 -d 10.213.0.18 -m comment --comment koi-run={RUN} -j ACCEPT".split()])
        box.conntrack_error = conntrack_failure("conntrack v1.4.8 (conntrack-tools): Operation failed: No such file or directory")
        with pytest.raises(net.Failed, match="Operation failed"):
            box.revoke(RUN)
        # The rules are gone, the state is there, and it names the subnet.
        assert box.clean()
        state = json.loads(box.state_file().read_text())
        assert (state["runId"], state["subnet"], state["subnets"], state["recovered"]) == (RUN, "10.213.0.16/28", ["10.213.0.16/28"], True)
        written = next(i for i, c in enumerate(box.calls) if c.startswith("iptables -w 5 -D "))
        assert box.calls[written - 1].startswith("iptables -w 5 -S")
        assert box.attest()["runs"] == [RUN]
        # The next revoke finds no rule, but the state still says what to flush.
        box.conntrack_error = None
        box.calls.clear()
        assert box.revoke(RUN) == {"runId": RUN, "removed": 0, "flushed": ["10.213.0.16/28"]}
        assert box.conntrack[-2:] == ["conntrack -D -s 10.213.0.16/28", "conntrack -D -d 10.213.0.16/28"]
        assert not box.state_file().exists()

    def test_a_flush_that_fails_keeps_the_state_and_is_not_a_success(self, box):
        desc = descriptor()
        box.docker(desc)
        box.apply(desc)
        for message in (
            "conntrack v1.4.8 (conntrack-tools): Operation failed: No such file or directory",
            "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\nsomething else",
            "0 flow entries have been deleted.",
        ):
            box.conntrack_error = conntrack_failure(message)
            with pytest.raises(net.Failed):
                box.revoke(RUN)
            assert box.state_file().exists()
        box.conntrack_error = net.Failed("conntrack -D -s 10.213.0.16/28 exited 2: usage", returncode=2, stderr="conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\n")
        with pytest.raises(net.Failed, match="exited 2"):
            box.revoke(RUN)
        assert box.state_file().exists()
        box.conntrack_error = net.Failed("conntrack is not installed")
        with pytest.raises(net.Failed, match="not installed"):
            box.revoke(RUN)
        assert box.state_file().exists()
        box.conntrack_error = None
        assert box.revoke(RUN)["flushed"] == ["10.213.0.16/28"]
        assert not box.state_file().exists()

    def test_only_the_zero_flows_message_with_exit_1_counts_as_nothing_to_flush(self, box):
        box.conntrack_error = net.Failed(
            "conntrack -D -s 10.213.0.16/28 exited 1: conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.",
            returncode=1,
            stderr="conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.\n",
        )
        net.flush_conntrack(box.run, ipaddress.ip_network("10.213.0.16/28"))
        assert box.conntrack == ["conntrack -D -s 10.213.0.16/28", "conntrack -D -d 10.213.0.16/28"]
        # Entries deleted: conntrack exits 0 and prints the count.
        box.conntrack_error = None
        box.answers["conntrack -D -s 10.213.0.16/28"] = ""
        box.answers["conntrack -D -d 10.213.0.16/28"] = ""
        net.flush_conntrack(box.run, ipaddress.ip_network("10.213.0.16/28"))

    def test_is_quiet_for_a_run_that_has_nothing(self, box):
        assert box.revoke(RUN) == {"runId": RUN, "removed": 0, "flushed": []}
        assert box.changes() == []
        assert box.conntrack == []

    def test_a_state_file_it_cannot_read_is_an_error_unless_the_rules_give_the_subnet(self, box):
        box.state.mkdir()
        box.state_file().write_text("{not json")
        with pytest.raises(net.Failed, match="unreadable.*no rule of run.*by hand"):
            box.revoke(RUN)
        assert box.state_file().exists()
        box.fw.command("iptables", ["-I", "KOI-VERIFY", "1", *f"-i {BRIDGE} -s 10.213.0.19 -m comment --comment koi-run={RUN} -j ACCEPT".split()])
        assert box.revoke(RUN) == {"runId": RUN, "removed": 1, "flushed": ["10.213.0.16/28"]}
        assert not box.state_file().exists()

    def test_finishes_a_swap_an_interrupted_provision_left_before_it_removes_the_run(self, box):
        """The staged chain is the live one and holds the permits; a revoke that only read the old chain would leave them, for the next provision to rename back."""
        desc = descriptor()
        box.docker(desc, running=("app", "recorder"))
        box.apply(desc)
        chains = box.fw.tables["iptables"]
        # Provision stopped right after the jump moved to the staged chain.
        chains["KOI-VERIFY-NEW"] = [list(r) for r in chains["KOI-VERIFY"]]
        chains["DOCKER-USER"].insert(0, ["-j", "KOI-VERIFY-NEW"])
        box.calls.clear()
        box.fw.watching = True
        result = box.revoke(RUN)
        assert result == {"runId": RUN, "removed": 9, "flushed": ["10.213.0.16/28"]}
        assert box.fw.unconfined_after == []
        assert not any(f"koi-run={RUN}" in r for rules in chains.values() for r in rules)
        assert "KOI-VERIFY-NEW" not in chains
        assert box.rules("DOCKER-USER")[0] == ["-j", "KOI-VERIFY"]
        assert box.clean()
        assert box.conntrack == ["conntrack -D -s 10.213.0.16/28", "conntrack -D -d 10.213.0.16/28"]
        assert not box.state_file().exists()
        # The swap is finished before any permit goes, and every permit goes before the flush.
        changes = box.changes()
        renamed = changes.index("iptables -w 5 -E KOI-VERIFY-NEW KOI-VERIFY")
        deletes = [i for i, c in enumerate(changes) if c.startswith("iptables -w 5 -D KOI-VERIFY")]
        assert len(deletes) == 9
        assert renamed < deletes[0]
        assert deletes[-1] < changes.index("conntrack -D -s 10.213.0.16/28")
        assert box.provision()["changed"] == []
        assert box.attest()["runs"] == []

    def test_removes_permits_left_in_a_staged_chain_when_the_old_chain_and_the_state_are_gone(self, box):
        """Provision stopped after the old chain went and before the staged one took its name; no apply recorded this run."""
        permit = f"-i {BRIDGE} -o {BRIDGE} -s 10.213.0.19 -d 10.213.0.18 -p tcp --dport 8080 -m comment --comment koi-run={RUN} -j ACCEPT"
        chains = box.fw.tables["iptables"]
        chains["KOI-VERIFY-NEW"] = [render(permit.split())] + [render(r) for r in net.BASE_FORWARD]
        chains["DOCKER-USER"][0] = ["-j", "KOI-VERIFY-NEW"]
        del chains["KOI-VERIFY"]
        assert not box.state_file().exists()
        assert box.revoke(RUN) == {"runId": RUN, "removed": 1, "flushed": ["10.213.0.16/28"]}
        assert not any(f"koi-run={RUN}" in r for rules in chains.values() for r in rules)
        assert "KOI-VERIFY-NEW" not in chains
        assert box.rules("DOCKER-USER")[0] == ["-j", "KOI-VERIFY"]
        assert box.clean()
        assert box.conntrack == ["conntrack -D -s 10.213.0.16/28", "conntrack -D -d 10.213.0.16/28"]
        assert not box.state_file().exists()
        assert box.attest()["ipv4"]["problems"] == []

    def test_searches_every_chain_with_the_helpers_prefix(self, box):
        """A permit in a chain of the helper's under a name it did not expect goes too."""
        permit = f"-i {BRIDGE} -s 10.213.0.19 -m comment --comment koi-run={RUN} -j ACCEPT"
        box.fw.tables["iptables"]["KOI-VERIFY-OLD"] = [render(permit.split())]
        box.fw.command("iptables", ["-I", "KOI-VERIFY-IN", "1", *permit.split()])
        assert box.revoke(RUN) == {"runId": RUN, "removed": 2, "flushed": ["10.213.0.16/28"]}
        assert box.rules("KOI-VERIFY-OLD") == []
        assert box.clean()
        assert "iptables -w 5 -S" in box.calls

    def test_a_listing_that_fails_is_not_a_success(self, box):
        # The run's rules come from one listing of the whole table.
        box.failing["iptables -w 5 -S"] = "iptables -w 5 -S exited 4: xtables lock"
        with pytest.raises(net.Failed, match="xtables lock"):
            box.revoke(RUN)
        # So does the look for a staged chain before it.
        del box.failing["iptables -w 5 -S"]
        box.failing["iptables -w 5 -S KOI-VERIFY-IN-NEW"] = "iptables -w 5 -S KOI-VERIFY-IN-NEW exited 4: xtables lock"
        with pytest.raises(net.Failed, match="xtables lock"):
            box.revoke(RUN)

    def test_refuses_a_run_id_of_the_wrong_shape(self, box):
        for bad in ("", "x", "UPPER" * 4, "a b c d e f g h i j k l m n o p", "../etc"):
            with pytest.raises(net.Refused):
                box.revoke(bad)
        assert box.calls == []


class TestAttest:
    def test_reports_a_provisioned_host(self, box):
        report = box.attest()
        assert report["policy"] == net.POLICY_VERSION
        assert report["pool"] == "10.213.0.0/20"
        assert report["ipv4"] == {"chains": True, "jump": True, "defaults": True, "permits": True, "problems": []}
        assert report["ipv6"] == {"defaults": True, "problems": []}
        assert report["sysctl"] == {
            "br_netfilter": True,
            "bridge_nf_call_iptables": True,
            "bridge_nf_call_ip6tables": True,
            "bridge_nf_filter_vlan_tagged": True,
        }
        assert report["bridge"] == {"guard": True, "pins": True, "problems": []}
        assert report["runs"] == []
        assert report["rules"]["KOI-VERIFY"] == [" ".join(render(r)) for r in net.BASE_FORWARD]
        json.dumps(report)

    def test_names_what_is_missing(self, box, monkeypatch):
        monkeypatch.setattr(net, "read_sysctl", lambda name: None)
        box.fw.command("iptables", ["-D", "INPUT", "-i", "kv+", "-j", "KOI-VERIFY-IN"])
        box.fw.command("iptables", ["-F", "KOI-VERIFY-IN"])
        box.fw.command("iptables", ["-X", "KOI-VERIFY-IN"])
        box.fw.command("iptables", ["-D", "DOCKER-USER", "-j", "KOI-VERIFY"])
        box.fw.command("ip6tables", ["-D", "OUTPUT", "-o", "kv+", "-j", "DROP"])
        del box.rules("KOI-VERIFY")[-1]
        box.env.write_text("")
        report = box.attest()
        assert report["pool"] is None
        assert (report["ipv4"]["chains"], report["ipv4"]["jump"], report["ipv4"]["defaults"], report["ipv4"]["permits"]) == (False, False, False, False)
        assert report["ipv4"]["problems"] == [
            "chain KOI-VERIFY does not end with its default denies",
            "chain KOI-VERIFY has a rule that is not a run permit above its defaults: -i kv+ -m conntrack --ctstate INVALID -j DROP",
            "chain KOI-VERIFY has a rule that is not a run permit above its defaults: -o kv+ -m conntrack --ctstate INVALID -j DROP",
            "chain KOI-VERIFY has a rule that is not a run permit above its defaults: -i kv+ -p udp -j DROP",
            "chain KOI-VERIFY has a rule that is not a run permit above its defaults: -d 224.0.0.0/4 -i kv+ -j DROP",
            "chain KOI-VERIFY has a rule that is not a run permit above its defaults: -d 169.254.0.0/16 -i kv+ -j DROP",
            "chain KOI-VERIFY has a rule that is not a run permit above its defaults: -i kv+ -p tcp -m tcp --dport 53 -j DROP",
            "chain KOI-VERIFY has a rule that is not a run permit above its defaults: -i kv+ -j DROP",
            "chain KOI-VERIFY-IN does not exist",
            "chain DOCKER-USER has no rule -j KOI-VERIFY",
            "chain INPUT has no rule -i kv+ -j KOI-VERIFY-IN",
        ]
        assert report["ipv6"] == {"defaults": False, "problems": ["ip6tables OUTPUT has no rule -o kv+ -j DROP"]}
        assert report["sysctl"] == {
            "br_netfilter": False,
            "bridge_nf_call_iptables": False,
            "bridge_nf_call_ip6tables": False,
            "bridge_nf_filter_vlan_tagged": False,
        }
        assert report["rules"]["KOI-VERIFY-IN"] == []

    def test_a_chain_listing_that_fails_for_another_reason_is_an_error(self, box):
        box.failing["iptables -w 5 -S KOI-VERIFY"] = "iptables -w 5 -S KOI-VERIFY exited 4: xtables lock"
        with pytest.raises(net.Failed, match="xtables lock"):
            box.attest()

    def test_the_jump_must_come_before_anything_that_could_let_kv_traffic_past(self, box):
        def problems():
            return box.attest()["ipv4"]["problems"]

        # DOCKER-USER: the jump must be the first rule, whatever is before it.
        box.fw.command("iptables", ["-I", "DOCKER-USER", "1", "-j", "RETURN"])
        assert problems() == ["chain DOCKER-USER does not start with -j KOI-VERIFY: its first rule is -j RETURN"]
        box.fw.command("iptables", ["-D", "DOCKER-USER", "1"])
        # FORWARD must reach DOCKER-USER before an accept that forwarded kv+ traffic could hit.
        for rule, bad in (
            ("-j ACCEPT", True),
            ("-i docker0 -j ACCEPT", True),
            ("-o kv0123456789ab -j ACCEPT", True),
            ("-j RETURN", True),
            ("-i docker0 -o docker0 -j ACCEPT", False),
            ("-i kv+ -j DROP", False),
            ("-m conntrack --ctstate INVALID -j LOG", False),
            ("-j DOCKER-ISOLATION-STAGE-1", False),
        ):
            box.fw.command("iptables", ["-I", "FORWARD", "1", *rule.split()])
            expected = [f"chain FORWARD reaches -j DOCKER-USER only after {' '.join(render(rule.split()))}"] if bad else []
            assert problems() == expected, rule
            box.fw.command("iptables", ["-D", "FORWARD", "1"])
        # INPUT: an accept that cannot match kv+ is fine; one that could is not.
        for rule, bad in (
            ("-i kv+ -j ACCEPT", True),
            ("-i kv0123456789ab -j ACCEPT", True),
            ("-i k+ -j ACCEPT", True),
            ("-j ACCEPT", True),
            ("! -i koi-previews0 -j ACCEPT", True),
            ("-i koi-previews0 -p tcp --dport 3128 -m conntrack --ctstate NEW -j ACCEPT", False),
            ("-i kv+ -m conntrack --ctstate NEW -j DROP", False),
            ("-i kv+ -j REJECT", False),
            ("-i kvx+ -j ACCEPT", False),
        ):
            box.fw.command("iptables", ["-I", "INPUT", "1", *rule.split()])
            expected = [f"chain INPUT reaches -i kv+ -j KOI-VERIFY-IN only after {' '.join(render(rule.split()))}"] if bad else []
            assert problems() == expected, rule
            box.fw.command("iptables", ["-D", "INPUT", "1"])
        box.fw.command("iptables", ["-I", "OUTPUT", "1", "-o", "kv+", "-j", "ACCEPT"])
        assert problems() == ["chain OUTPUT reaches -o kv+ -j KOI-VERIFY-OUT only after -o kv+ -j ACCEPT"]
        box.fw.command("iptables", ["-D", "OUTPUT", "1"])
        assert problems() == []

    def test_a_jump_before_the_guard_is_followed_into_its_chain(self, box):
        box.fw.command("iptables", ["-N", "ufw-before-input"])
        box.fw.command("iptables", ["-A", "ufw-before-input", "-i", "lo", "-j", "ACCEPT"])
        box.fw.command("iptables", ["-A", "ufw-before-input", "-j", "RETURN"])
        box.fw.command("iptables", ["-I", "INPUT", "1", "-j", "ufw-before-input"])
        assert box.attest()["ipv4"]["problems"] == []
        box.fw.command("iptables", ["-I", "ufw-before-input", "1", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT"])
        assert box.attest()["ipv4"]["problems"] == [
            "chain INPUT reaches -i kv+ -j KOI-VERIFY-IN only after -j ufw-before-input"
            " (chain ufw-before-input: -m conntrack --ctstate ESTABLISHED -j ACCEPT)"
        ]
        # A target that is not a chain cannot be followed, so it counts.
        box.fw.command("iptables", ["-D", "ufw-before-input", "1"])
        box.fw.command("iptables", ["-I", "INPUT", "1", "-j", "MARK", "--set-mark", "1"])
        assert box.attest()["ipv4"]["problems"] == ["chain INPUT reaches -i kv+ -j KOI-VERIFY-IN only after -j MARK --set-mark 1"]

    def test_a_comment_cannot_hide_an_accept_from_the_jump_check(self, box):
        """Each odd rule before the jump is reported with the rule as the listing printed it, read from the literal text, not from the stand-in."""
        header, *lines, guard = LISTING_INPUT_ODD.splitlines()
        reported = [
            "-i kv+ -m comment --comment '!' -j ACCEPT",
            "-i kv+ -m comment --comment 'a comment, with spaces and \"quotes\" and -j DROP in it' -j ACCEPT",
            "-i kv+ -m comment --comment -j -j ACCEPT",
            # A negated interface counts as able to match, as every option but a plain -i or -o does.
            "! -i kv+ -j ACCEPT",
        ]
        for line, text in zip(lines, reported):
            box.answers["iptables -w 5 -S INPUT"] = f"{header}\n{line}\n{guard}\n"
            assert box.attest()["ipv4"]["problems"] == [f"chain INPUT reaches -i kv+ -j KOI-VERIFY-IN only after {text}"], line
        box.answers["iptables -w 5 -S INPUT"] = f"{header}\n{guard}\n" + "\n".join(lines) + "\n"
        assert box.attest()["ipv4"]["problems"] == []

    def test_a_rule_it_cannot_read_in_full_is_never_harmless(self, box):
        """An option the parser does not know could take anything after it, so the rule counts as one that could let traffic past, deny or not."""
        odd = "-i kv+ -m made-up --made-up-option 3 -j DROP"
        reason = "option --made-up-option is not one koi-verify-net knows"
        box.answers["iptables -w 5 -S INPUT"] = f"-P INPUT ACCEPT\n-A INPUT {odd}\n-A INPUT -i kv+ -j KOI-VERIFY-IN\n"
        assert box.attest()["ipv4"]["problems"] == [f"chain INPUT reaches -i kv+ -j KOI-VERIFY-IN only after {odd} (not read in full: {reason})"]
        del box.answers["iptables -w 5 -S INPUT"]
        # The same rule above a chain's defaults is reported, not taken for a permit or a default.
        base = "".join(f"-A KOI-VERIFY {' '.join(r)}\n" for r in net.BASE_FORWARD)
        box.answers["iptables -w 5 -S KOI-VERIFY"] = f"-N KOI-VERIFY\n-A KOI-VERIFY {odd} -m comment --comment koi-run={RUN}\n{base}"
        report = box.attest()["ipv4"]
        assert report["permits"] is False
        assert report["problems"] == [f"chain KOI-VERIFY has a rule above its defaults that koi-verify-net cannot read in full ({reason}): {odd} -m comment --comment koi-run={RUN}"]
        # Inside a chain the jump check follows, too.
        del box.answers["iptables -w 5 -S KOI-VERIFY"]
        box.fw.command("iptables", ["-N", "before-input"])
        box.answers["iptables -w 5 -S before-input"] = f"-N before-input\n-A before-input {odd}\n-A before-input -j RETURN\n"
        box.fw.command("iptables", ["-I", "INPUT", "1", "-j", "before-input"])
        assert box.attest()["ipv4"]["problems"] == [
            f"chain INPUT reaches -i kv+ -j KOI-VERIFY-IN only after -j before-input (chain before-input: {odd} (not read in full: {reason}))"
        ]

    def test_the_chains_hold_only_the_permits_of_recorded_runs_above_their_defaults(self, box):
        desc = descriptor()
        box.docker(desc, running=("app",))
        box.apply(desc)
        assert box.attest()["ipv4"]["permits"] is True

        def problems():
            return [p for p in box.attest()["ipv4"]["problems"] if p.startswith("chain KOI-VERIFY ")]

        stray = f"-i {BRIDGE} -o {BRIDGE} -s 10.213.0.35 -d 10.213.0.34 -p tcp --dport 80 -m comment --comment koi-run={OTHER} -j ACCEPT"
        box.fw.command("iptables", ["-I", "KOI-VERIFY", "1", *stray.split()])
        assert problems() == [f"chain KOI-VERIFY has a permit of run {OTHER}, which has no state file: {' '.join(render(stray.split()))}"]
        assert box.attest()["ipv4"]["permits"] is False
        box.fw.command("iptables", ["-D", "KOI-VERIFY", "1"])
        # A rule with the run's comment that its state does not describe.
        forged = f"-i {BRIDGE} -o {BRIDGE} -s 10.213.0.18 -d 10.213.0.19 -p tcp --dport 4318 -m comment --comment koi-run={RUN} -j ACCEPT"
        box.fw.command("iptables", ["-I", "KOI-VERIFY", "1", *forged.split()])
        assert problems() == [f"chain KOI-VERIFY has a permit of run {RUN} that its state does not describe: {' '.join(render(forged.split()))}"]
        box.fw.command("iptables", ["-D", "KOI-VERIFY", "1"])
        # A rule without a comment, and a rule below the defaults.
        box.fw.command("iptables", ["-I", "KOI-VERIFY", "1", "-i", "kv+", "-j", "ACCEPT"])
        assert problems() == ["chain KOI-VERIFY has a rule that is not a run permit above its defaults: -i kv+ -j ACCEPT"]
        box.fw.command("iptables", ["-D", "KOI-VERIFY", "1"])
        box.fw.command("iptables", ["-A", "KOI-VERIFY", "-i", "kv+", "-j", "ACCEPT"])
        report = box.attest()["ipv4"]
        assert report["defaults"] is False
        assert report["problems"][0] == "chain KOI-VERIFY does not end with its default denies"
        assert any("-i kv+ -j ACCEPT" in p for p in report["problems"])

    def test_a_state_written_by_revoke_describes_no_permits(self, box):
        box.state.mkdir()
        box.state_file().write_text(json.dumps({"runId": RUN, "subnet": "10.213.0.16/28", "subnets": ["10.213.0.16/28"], "recovered": True}))
        box.fw.command("iptables", ["-I", "KOI-VERIFY", "1", *f"-i {BRIDGE} -s 10.213.0.19 -m comment --comment koi-run={RUN} -j ACCEPT".split()])
        report = box.attest()
        assert report["runs"] == [RUN]
        assert report["ipv4"]["permits"] is False
        assert report["ipv4"]["problems"] == [
            f"chain KOI-VERIFY has a permit of run {RUN} that its state does not describe: -s 10.213.0.19/32 -i {BRIDGE} -m comment --comment koi-run={RUN} -j ACCEPT"
        ]

    def test_ipv6_denies_must_come_before_an_accept_too(self, box):
        box.fw.command("ip6tables", ["-I", "INPUT", "1", "-j", "ACCEPT"])
        box.fw.command("ip6tables", ["-I", "FORWARD", "1", "-i", "docker0", "-j", "ACCEPT"])
        assert box.attest()["ipv6"] == {
            "defaults": False,
            "problems": [
                "ip6tables INPUT reaches -i kv+ -j DROP only after -j ACCEPT",
                "ip6tables FORWARD reaches -i kv+ -j DROP only after -i docker0 -j ACCEPT",
                "ip6tables FORWARD reaches -o kv+ -j DROP only after -i docker0 -j ACCEPT",
            ],
        }
        box.fw.command("ip6tables", ["-D", "INPUT", "1"])
        box.fw.command("ip6tables", ["-D", "FORWARD", "1"])
        # Docker's own jump sits before them in FORWARD and only returns.
        box.fw.command("ip6tables", ["-I", "FORWARD", "1", "-j", "DOCKER-USER"])
        assert box.attest()["ipv6"] == {"defaults": True, "problems": []}


class TestKernelMessage:
    """Kernel 7.0 with iptables-nft 1.8.10 reports a missing chain as "Incompatible with this kernel"."""

    def test_provision_apply_and_revoke_work_when_a_missing_chain_is_reported_that_way(self, box):
        box.fw.incompatible = True
        assert box.provision()["changed"] == []
        desc = descriptor()
        box.docker(desc, running=("app",))
        assert box.apply(desc)["rules"] == 9
        assert box.attest()["ipv4"]["permits"] is True
        assert box.revoke(RUN)["removed"] == 9
        assert box.clean()
        # Each "missing" was checked against a listing of the whole table.
        assert "iptables -w 5 -S" in box.calls

    def test_the_message_for_a_chain_that_exists_is_an_error(self, box):
        box.fw.incompatible = True
        box.failing["iptables -w 5 -S KOI-VERIFY"] = net.Failed(
            "iptables -w 5 -S KOI-VERIFY exited 1: iptables: Incompatible with this kernel.", returncode=1
        )
        with pytest.raises(net.Failed, match="Incompatible"):
            box.attest()
        with pytest.raises(net.Failed, match="Incompatible"):
            box.provision()

    def test_a_table_listing_that_names_no_built_in_chain_proves_nothing(self, box):
        box.fw.incompatible = True
        box.answers["iptables -w 5 -S"] = "-N KOI-VERIFY\n"
        with pytest.raises(net.Failed, match="does not list the INPUT, FORWARD and OUTPUT chains"):
            net.listing(box.run, "KOI-VERIFY-NEW")
        # Without the message, nothing changes: "No chain" is missing as before.
        box.fw.incompatible = False
        assert net.listing(box.run, "KOI-VERIFY-NEW") is None


class TestBridgeSysctls:
    def test_provision_turns_on_the_filtering_of_vlan_tagged_frames(self, box, monkeypatch):
        values = {"net.bridge.bridge-nf-filter-vlan-tagged": "0"}
        written = []
        monkeypatch.setattr(net, "read_sysctl", lambda name: values.get(name, "1"))
        monkeypatch.setattr(net, "write_sysctl", lambda name, value: written.append((name, value)) or values.update({name: value}))
        assert box.attest()["sysctl"]["bridge_nf_filter_vlan_tagged"] is False
        result = box.provision()
        assert written == [("net.bridge.bridge-nf-filter-vlan-tagged", "1")]
        assert result["changed"] == ["set net.bridge.bridge-nf-filter-vlan-tagged to 1"]
        assert result["sysctl"]["bridge_nf_filter_vlan_tagged"] is True
        assert box.provision()["changed"] == []

    def test_without_br_netfilter_there_is_nothing_to_set_and_attest_says_so(self, box, monkeypatch):
        monkeypatch.setattr(net, "read_sysctl", lambda name: None)
        assert box.provision()["changed"] == []
        report = box.attest()["sysctl"]
        assert report["br_netfilter"] is False
        assert report["bridge_nf_filter_vlan_tagged"] is False


class TestLayer2:
    """Only plain IPv4 and ARP cross a kv+ bridge: br_netfilter never shows iptables a frame under two VLAN tags."""

    def test_attest_names_a_missing_jump_a_jump_behind_another_rule_and_a_changed_chain(self, box):
        assert box.attest()["bridge"]["guard"] is True
        box.l2.ebtables["FORWARD"].insert(0, ["-j", "ACCEPT"])
        box.l2.ebtables["KOI-VERIFY-L2"].insert(2, ["-p", "802_1Q", "-j", "RETURN"])
        report = box.attest()["bridge"]
        assert report["guard"] is False
        assert report["problems"] == [
            "ebtables FORWARD does not start with --logical-in kv+ -j KOI-VERIFY-L2: its first rule is -j ACCEPT",
            "ebtables chain KOI-VERIFY-L2 holds -p IPv4 -j RETURN; -p ARP -j RETURN; -p 802_1Q -j RETURN; -j DROP, not the allowlist",
        ]
        del box.l2.ebtables["KOI-VERIFY-L2"]
        box.l2.ebtables["FORWARD"] = []
        assert box.attest()["bridge"]["problems"] == [
            "ebtables FORWARD has no rule --logical-in kv+ -j KOI-VERIFY-L2",
            "ebtables chain KOI-VERIFY-L2 does not exist",
        ]

    def test_a_protocol_given_as_a_number_is_the_same_rule(self):
        assert net.l2_rule(["-p", "0x0800", "-j", "RETURN"]) == net.l2_rule(["-p", "IPv4", "-j", "RETURN"])
        assert net.l2_rule(["-p", "ARP", "-j", "RETURN"]) == ["-p", "0x0806", "-j", "RETURN"]
        assert net.l2_rule(["-p", "802_1Q", "-j", "RETURN"]) != net.l2_rule(["-p", "IPv4", "-j", "RETURN"])

    def test_provision_repairs_the_chain_dropping_first_and_puts_the_jump_back_in_front(self, box):
        box.l2.ebtables["KOI-VERIFY-L2"] = [["-j", "ACCEPT"]]
        box.l2.ebtables["FORWARD"] = [["-j", "ACCEPT"], ["--logical-in", "kv+", "-j", "KOI-VERIFY-L2"]]
        box.calls.clear()
        result = box.provision()
        assert result["changed"] == [
            "rebuilt ebtables chain KOI-VERIFY-L2",
            "ebtables FORWARD: inserted --logical-in kv+ -j KOI-VERIFY-L2 first",
            "ebtables FORWARD: removed a later copy of --logical-in kv+ -j KOI-VERIFY-L2",
        ]
        # The drop goes in above what was there before anything that lets a frame through.
        assert [c for c in box.changes() if c.startswith("ebtables")][:4] == [
            "ebtables -t filter -I KOI-VERIFY-L2 1 -j DROP",
            "ebtables -t filter -I KOI-VERIFY-L2 1 -p ARP -j RETURN",
            "ebtables -t filter -I KOI-VERIFY-L2 1 -p IPv4 -j RETURN",
            "ebtables -t filter -D KOI-VERIFY-L2 4",
        ]
        assert box.l2.ebtables["KOI-VERIFY-L2"] == [["-p", "IPv4", "-j", "RETURN"], ["-p", "ARP", "-j", "RETURN"], ["-j", "DROP"]]
        assert box.l2.ebtables["FORWARD"] == [["--logical-in", "kv+", "-j", "KOI-VERIFY-L2"], ["-j", "ACCEPT"]]
        assert result["bridge"]["guard"] is True
        assert box.provision()["changed"] == []


class TestPins:
    """Once an endpoint runs, its MAC is a static sticky entry on its own port, and the recorder's address a permanent neighbour of the host."""

    RECORDER_MAC = "02:4b:0a:d5:00:13"

    def test_apply_pins_each_running_endpoint_before_the_first_permit(self, box):
        desc = descriptor()
        box.docker(desc, running=net.ROLES)
        box.apply(desc)
        changes = box.changes()
        pins = [
            "bridge fdb replace 02:42:0a:d5:00:12 dev vethapp master static sticky",
            "bridge fdb replace 02:4b:0a:d5:00:13 dev vethrecorder master static sticky",
            "bridge fdb replace 02:4b:0a:d5:00:14 dev vethverifier master static sticky",
            f"ip neigh replace 10.213.0.19 lladdr 02:4b:0a:d5:00:13 dev {BRIDGE} nud permanent",
        ]
        assert changes[: len(pins)] == pins
        assert all(c.startswith("iptables -w 5 -I ") for c in changes[len(pins):])
        assert box.pins() == (
            [("02:42:0a:d5:00:12", "vethapp"), ("02:4b:0a:d5:00:13", "vethrecorder"), ("02:4b:0a:d5:00:14", "vethverifier")],
            [("10.213.0.19", "02:4b:0a:d5:00:13")],
        )
        assert box.attest()["bridge"] == {"guard": True, "pins": True, "problems": []}

    def test_a_frame_from_another_port_cannot_move_a_pin(self, box):
        desc = descriptor()
        box.docker(desc, running=("app", "recorder"))
        box.apply(desc)
        box.links.append({"ifindex": 999, "ifname": "vethattacker", "master": BRIDGE})
        box.l2.learned(self.RECORDER_MAC, "vethattacker", BRIDGE)
        assert ("02:4b:0a:d5:00:13", "vethrecorder") in box.pins()[0]
        assert box.attest()["bridge"]["pins"] is True

    def test_attest_names_a_pin_that_is_missing_or_moved_and_a_neighbour_that_changed(self, box):
        desc = descriptor()
        box.docker(desc, running=("app", "recorder"))
        box.apply(desc)
        box.links.append({"ifindex": 999, "ifname": "vethattacker", "master": BRIDGE})
        box.l2.bridge_command(["bridge", "fdb", "del", "02:42:0a:d5:00:12", "dev", "vethapp", "master"], box.links)
        box.l2.bridge_command(["bridge", "fdb", "replace", self.RECORDER_MAC, "dev", "vethattacker", "master", "static", "sticky"], box.links)
        box.l2.neigh_command(["ip", "neigh", "replace", "10.213.0.19", "lladdr", "02:66:00:00:00:01", "dev", BRIDGE, "nud", "permanent"])
        report = box.attest()["bridge"]
        assert report["pins"] is False
        assert report["problems"] == [
            f"run {RUN}: 02:42:0a:d5:00:12 is not pinned to vethapp on {BRIDGE}; the bridge has it nowhere",
            f"run {RUN}: 02:4b:0a:d5:00:13 is not pinned to vethrecorder on {BRIDGE}; the bridge has it vethattacker static, vethattacker static",
            f"run {RUN}: the host does not hold 10.213.0.19 at 02:4b:0a:d5:00:13 on {BRIDGE} as a permanent neighbour",
        ]
        # A learned entry where the pin should be is no pin either.
        box.apply(desc)
        assert box.attest()["bridge"]["pins"] is True
        box.l2.fdb = [e for e in box.l2.fdb if e["mac"] != self.RECORDER_MAC]
        box.l2.learned(self.RECORDER_MAC, "vethattacker", BRIDGE)
        assert box.attest()["bridge"]["problems"] == [
            f"run {RUN}: 02:4b:0a:d5:00:13 is not pinned to vethrecorder on {BRIDGE}; the bridge has it vethattacker learned"
        ]

    def test_attest_names_a_pin_no_state_describes_and_skips_a_port_that_is_gone(self, box):
        desc = descriptor()
        box.docker(desc, running=("app", "recorder"))
        box.apply(desc)
        # The recorder stopped: Docker removed its port, and the kernel the pin with it.
        box.links = [link for link in box.links if link["ifname"] != "vethrecorder"]
        box.l2.fdb = [e for e in box.l2.fdb if e["ifname"] != "vethrecorder"]
        assert box.attest()["bridge"]["pins"] is True
        # A static entry or a permanent neighbour on a kv bridge that no run's state calls for.
        box.links.append({"ifindex": 998, "ifname": "vethstray", "master": OTHER_BRIDGE})
        box.l2.bridge_command(["bridge", "fdb", "replace", "02:4b:0a:d5:00:99", "dev", "vethstray", "master", "static", "sticky"], box.links)
        box.l2.neigh_command(["ip", "neigh", "replace", "10.213.0.35", "lladdr", "02:4b:0a:d5:00:99", "dev", OTHER_BRIDGE, "nud", "permanent"])
        assert box.attest()["bridge"]["problems"] == [
            f"bridge {OTHER_BRIDGE} has a static entry no run's state describes: 02:4b:0a:d5:00:99 on vethstray",
            f"bridge {OTHER_BRIDGE} has a static entry no run's state describes: 02:4b:0a:d5:00:99 on vethstray",
            f"bridge {OTHER_BRIDGE} has a permanent neighbour no run's state describes: 10.213.0.35 at 02:4b:0a:d5:00:99",
        ]

    def test_a_second_apply_moves_a_pin_to_a_new_port_and_drops_what_the_ports_no_longer_call_for(self, box):
        desc = descriptor()
        box.docker(desc, running=net.ROLES)
        box.apply(desc)
        # The verifier was made again for the next point: a new port, and the old one is still there.
        box.links.append({"ifindex": 997, "ifname": "vethverifier2", "master": BRIDGE})
        key = "nsenter --net=/var/run/docker/netns/verifier -- ip -j link show"
        inside = json.loads(box.answers[key])
        inside[0]["link_index"] = 997
        box.answers[key] = json.dumps(inside)
        box.apply(desc)
        assert ("02:4b:0a:d5:00:14", "vethverifier2") in box.pins()[0]
        assert ("02:4b:0a:d5:00:14", "vethverifier") not in box.pins()[0]
        # The recorder stopped: its pin and the host's neighbour go.
        box.docker(desc, running=("app",))
        box.apply(desc)
        assert box.pins() == ([("02:42:0a:d5:00:12", "vethapp")], [])
        assert box.attest()["bridge"]["pins"] is True

    def test_revoke_removes_the_runs_pins_and_leaves_another_runs_alone(self, box):
        desc = descriptor()
        box.docker(desc, running=net.ROLES)
        box.apply(desc)
        other = other_descriptor()
        box.docker(other, running=net.ROLES)
        box.apply(other)
        assert len(box.pins()[0]) == 6
        box.calls.clear()
        box.revoke(RUN)
        assert box.pins() == (
            [("02:42:0a:d5:00:22", "vethapp2"), ("02:4b:0a:d5:00:23", "vethrecorder2"), ("02:4b:0a:d5:00:24", "vethverifier2")],
            [("10.213.0.35", "02:4b:0a:d5:00:23")],
        )
        unpins = [c for c in box.changes() if c.startswith(("bridge", "ip neigh"))]
        assert unpins == [
            "bridge fdb del 02:42:0a:d5:00:12 dev vethapp master",
            "bridge fdb del 02:4b:0a:d5:00:13 dev vethrecorder master",
            "bridge fdb del 02:4b:0a:d5:00:14 dev vethverifier master",
            f"ip neigh del 10.213.0.19 dev {BRIDGE}",
        ]
        # They go after the permits, and before the state file, so a revoke that stops can be run again.
        changes = box.changes()
        assert changes.index(unpins[0]) > max(i for i, c in enumerate(changes) if c.startswith("iptables -w 5 -D "))
        assert box.attest()["bridge"] == {"guard": True, "pins": True, "problems": []}

    def test_revoke_without_a_state_file_finds_the_bridge_in_the_rules(self, box):
        desc = descriptor()
        box.docker(desc, running=("app", "recorder"))
        box.apply(desc)
        box.state_file().unlink()
        box.revoke(RUN)
        assert box.pins() == ([], [])


class TestMain:
    def test_prints_json_and_exits_0(self, box, monkeypatch):
        monkeypatch.setattr(net, "ENV_FILE", str(box.env))
        monkeypatch.setattr(net, "STATE_DIR", str(box.state))
        monkeypatch.setattr(net, "LOCK_FILE", str(box.lock))
        out, err = io.StringIO(), io.StringIO()
        assert net.main(["attest"], stdout=out, stderr=err, run=box.run) == 0
        assert json.loads(out.getvalue())["pool"] == "10.213.0.0/20"
        assert err.getvalue() == ""
        out = io.StringIO()
        assert net.main(["provision"], stdout=out, stderr=err, run=box.run) == 0
        assert json.loads(out.getvalue())["changed"] == []
        desc = descriptor()
        box.docker(desc)
        out = io.StringIO()
        assert net.main(["apply"], stdin=io.StringIO(json.dumps(desc)), stdout=out, stderr=err, run=box.run) == 0
        assert json.loads(out.getvalue())["rules"] == 9
        out = io.StringIO()
        assert net.main(["revoke", RUN], stdout=out, stderr=err, run=box.run) == 0
        assert json.loads(out.getvalue())["removed"] == 9
        assert box.clean()

    def test_exits_2_with_the_reason_for_bad_input(self, box, monkeypatch):
        monkeypatch.setattr(net, "ENV_FILE", str(box.env))
        out, err = io.StringIO(), io.StringIO()
        assert net.main(["apply"], stdin=io.StringIO("nope"), stdout=out, stderr=err, run=box.run) == 2
        assert err.getvalue() == "koi-verify-net: refused: the descriptor is not JSON\n"
        assert out.getvalue() == ""
        assert box.calls == []

    def test_takes_exactly_the_four_commands(self):
        for argv in ([], ["apply", "x"], ["revoke"], ["revoke", RUN, RUN], ["attest", "--all"], ["provision", "now"], ["flush"]):
            err = io.StringIO()
            assert net.main(argv, stdin=io.StringIO(""), stdout=io.StringIO(), stderr=err, run=lambda a, s=None: "") == 2
            assert err.getvalue().startswith("usage:")
            assert "provision" in err.getvalue()

    def test_exits_1_when_a_command_fails(self, tmp_path, monkeypatch):
        # On a box the real state directory is root's alone; this test is not about it.
        monkeypatch.setattr(net, "STATE_DIR", str(tmp_path / "state"))

        def broken(argv, stdin=None):
            raise net.Failed("iptables -w 5 -S exited 4: xtables lock")

        err = io.StringIO()
        assert net.main(["attest"], stdout=io.StringIO(), stderr=err, run=broken) == 1
        assert "xtables lock" in err.getvalue()


class TestInstalledFile:
    def test_is_executable_python_with_only_the_standard_library(self):
        text = HELPER.read_text()
        assert text.startswith("#!/usr/bin/env python3\n")
        imports = {line.split()[1].split(".")[0] for line in text.splitlines() if line.startswith(("import ", "from "))}
        assert imports <= {"fcntl", "ipaddress", "json", "os", "pwd", "re", "shlex", "subprocess", "sys"}
        assert HELPER.stat().st_mode & 0o111, "the file in the repo is executable, as the installed one is"

    def test_provisioning_leaves_the_rules_to_the_helper(self):
        script = (HELPER.parent.parent / "cloud-init.sh").read_text()
        firewall = script.split("cat > /usr/local/sbin/koi-firewall <<'FW'\n", 1)[1].split("\nFW\n", 1)[0]
        assert "/usr/local/libexec/koi-verify-net" in firewall
        assert '"$KOI_VERIFY_NET" provision' in firewall
        # No rule of the chains is written by hand: the helper owns them.
        commands = [line for line in firewall.splitlines() if line.lstrip().startswith(("iptables", "ip6tables"))]
        assert commands, "koi-firewall still writes the preview rules itself"
        assert not any("KOI-VERIFY" in c or "kv+" in c for c in commands)
        assert "reset_defaults" not in script
        assert "/etc/sudoers.d/koi-verify-net" in script
        assert net.ENV_FILE in script
        install = (HELPER.parent / "install.sh").read_text()
        assert '"$TARGET" provision' in install


@pytest.mark.skipif(os.geteuid() != 0, reason="reads the live firewall as root")
def test_live_attest_runs_as_root():
    report = net.attest(net.run_command)
    assert report["policy"] == net.POLICY_VERSION
