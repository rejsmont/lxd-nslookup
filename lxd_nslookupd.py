#!/usr/bin/env python3
"""
LXD -> PowerDNS remote backend (HTTP connector, RESTful mode).

Serves forward zones (e.g. int.vibfolks.eu, lxd) and optional reverse zones
from live LXD state plus a static table in the config file. It has no
database dependency, so it can stand in for the database-backed
int.vibfolks.eu: dnsdist prefers the database instance and falls over to
this one when the database is gone.

Resolving <label>.<zone> (labels may contain dots):
  1. a container or VM named <label>
       running -> its published addresses; stopped -> name exists, no data
  2. an entry in `aliases`
       IP literals, other names (containers or aliases, recursively) and
       regexes over container names, in any mix
  3. otherwise: NXDOMAIN in an `auth` zone, SERVFAIL in a `fallback` zone
The same labels exist in every forward zone, so `x.lxd` and
`x.int.vibfolks.eu` answer the same way.

Zone modes:
  auth      this daemon is the only source for the zone: a name it doesn't
            know does not exist (NXDOMAIN). Use for `lxd`.
  fallback  the zone's real data lives elsewhere (the database-backed
            PowerDNS); this daemon only knows a subset. A name it doesn't
            know gets SERVFAIL, which resolvers don't cache as "does not
            exist" and which makes glibc move on to the next search domain.
            Names it does know are answered normally.
  In a fallback zone, a stopped instance (or an alias with no addresses)
  also gets SERVFAIL: the daemon can't say what the real zone holds for it.
  Probes PowerDNS makes while answering get an empty answer in both modes,
  so they can't turn a known name into SERVFAIL: ancestors of known names
  (it looks up glances.<zone> before answering x.glances.<zone>, and every
  nibble above a PTR), wildcard names (*.<zone>), and NS, DS and non-apex
  SOA lookups.
  PowerDNS asks the backend for ANY and filters by type itself, so a known
  name asked for a type this daemon doesn't serve (MX, TXT, SRV...) still
  gets NODATA, in both modes. Keep soa.minimum low to limit how long that is
  cached.

Design (unchanged from the previous version):
  * One LXD call (GET /1.0/instances?recursion=2) returns every instance with
    its state, cluster-wide. The reduced result is kept as a snapshot for
    `cache_ttl` seconds; lookups are dict lookups.
  * If LXD stops answering, the last good snapshot is served for up to
    `stale_ttl` seconds, then lookups fail with HTTP 503, which PowerDNS turns
    into SERVFAIL (not a negatively cached NXDOMAIN).
  * Handlers are synchronous, so FastAPI runs them in its thread pool and a
    slow LXD call never blocks the event loop.

Configuration (YAML, default /etc/lxd_nslookup.yml):
  lxd_client:                  # omit endpoint to use the local unix socket
    endpoint: https://...
    cert_file: /path/client.crt
    key_file: /path/client.key
    verify_cert: true
    project: default
    timeout: 1.5               # keep below the PowerDNS remote timeout
  server:
    host: "::1"
    port: 8053
  zones:                                 # zone: auth | fallback
    int.vibfolks.eu: fallback
    lxd: auth
  # zones: [lxd]                         # list form (or legacy 'domains'):
                                         # every zone is auth
  reverse_zones:                         # optional, PTR from the same data
    1.5.e.8.f.3.2.e.6.f.d.f.ip6.arpa: fallback
  ptr_zone: int.vibfolks.eu              # PTR targets: <label>.<ptr_zone>
  publish:                               # interface -> families to publish
    eth1: [inet6]
    eth0: [inet]
  # interface: eth1                      # legacy: one interface, both families
  ttl: 300
  cache_ttl: 10
  stale_ttl: 300
  health_label: _lxd-health              # TXT at <label> and <anything>.<label>,
                                         # answered only with LXD data
  aliases:
    vf-srv-a1: [fdf6:e23f:8e51:72f1::1, 192.0.2.1]   # IP literals
    ha-pool: {regex: '^ha-srv-a[12]$'}               # regex over instances
    ha-old: '^ha-srv-.*'                             # legacy regex string
    monitor: ha-pool                                 # another name
    web: [web-srv-l1, web-srv-l2, 192.0.2.80]        # mix
  soa:
    primary_ns: name-srv-a1.int.vibfolks.eu
    admin_email: hostmaster@vibfolks.eu
    ttl: 300
    minimum: 60
    refresh: 3600
    retry: 1800
    expire: 604800

A bare string alias is an IP literal if it parses as one, a regex if it
contains any of ^ $ * + ? [ ] ( ) { } | \\, and a name otherwise.
Aliases are flattened into A/AAAA records (no CNAMEs), so they keep working
even when the target name only exists in this backend.

Command line:
  lxd_nslookupd [-c CONFIG] [-d]          run the service
  lxd_nslookupd --dump ZONE               print the zone as it would be served
                                          now, for diffing against
                                          `pdnsutil list-zone`
"""
import argparse
import ipaddress
import logging
import re
import sys
import threading
import time
import warnings

import yaml

try:  # only needed when talking to LXD / serving HTTP
    import pylxd
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:  # pragma: no cover
    pylxd = None

from fastapi import FastAPI, HTTPException

warnings.filterwarnings("ignore", category=UserWarning, module="pylxd.models._model")

log = logging.getLogger("lxd_nslookupd")
app = FastAPI()

config = {}
client = None
zones = []          # forward zones, normalised, longest first
reverse_zones = []  # reverse zones, normalised, longest first
zone_modes = {}     # zone -> "auth" | "fallback"
ptr_zone = ""
publish = {}        # iface -> ("inet", "inet6") subset
aliases = {}        # label -> Alias
snapshot = None     # Snapshot instance

REGEX_CHARS = set("^$*+?[](){}|\\")
ZONE_MODES = ("auth", "fallback")
STRUCTURAL_QTYPES = ("NS", "DS", "SOA")
MAX_DEPTH = 8


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def norm(name):
    return str(name).strip().strip(".").lower()


def parse_ip(s):
    try:
        return ipaddress.ip_address(str(s).strip())
    except ValueError:
        return None


class Alias:
    """Parsed alias: literal addresses, referenced names and regexes."""

    __slots__ = ("label", "ips", "names", "regexes")

    def __init__(self, label):
        self.label = label
        self.ips = []       # ipaddress objects, config order
        self.names = []     # normalised labels
        self.regexes = []   # compiled patterns

    def add(self, item):
        if isinstance(item, dict):
            pattern = item.get("regex")
            if pattern is None:
                raise ValueError(f"unknown mapping {item!r} (expected {{regex: ...}})")
            self.regexes.append(re.compile(str(pattern)))
            return
        if isinstance(item, (int, float)):
            raise ValueError(f"unexpected number {item!r}")
        s = str(item).strip()
        ip = parse_ip(s)
        if ip is not None:
            self.ips.append(ip)
        elif REGEX_CHARS & set(s):
            self.regexes.append(re.compile(s))
        else:
            self.names.append(norm(s))

    @property
    def literal_only(self):
        return bool(self.ips) and not self.names and not self.regexes


def parse_aliases(raw):
    result = {}
    for label, target in (raw or {}).items():
        label = norm(label)
        alias = Alias(label)
        items = target if isinstance(target, list) else [target]
        try:
            for item in items:
                alias.add(item)
        except (ValueError, re.error) as e:
            log.warning("Ignoring alias %r: %s", label, e)
            continue
        if not (alias.ips or alias.names or alias.regexes):
            log.warning("Ignoring alias %r: empty", label)
            continue
        result[label] = alias
    check_alias_graph(result)
    return result


def check_alias_graph(table):
    """Warn once, at load time, about alias loops and over-deep nesting."""
    reported = set()

    def walk(label, path):
        for name in table[label].names:
            if name in path:
                cycle = " -> ".join(path[path.index(name):] + [name])
                if frozenset(path[path.index(name):]) not in reported:
                    reported.add(frozenset(path[path.index(name):]))
                    log.warning("Alias loop: %s (the looping branch is ignored)", cycle)
            elif name in table:
                if len(path) > MAX_DEPTH:
                    log.warning("Alias %s nested deeper than %d; deeper levels ignored",
                                path[0], MAX_DEPTH)
                    return
                walk(name, path + [name])

    for label in table:
        walk(label, [label])


def parse_publish(cfg):
    if "publish" in cfg:
        out = {}
        for iface, fams in (cfg.get("publish") or {}).items():
            fams = [fams] if isinstance(fams, str) else (fams or [])
            fams = tuple(f for f in ("inet", "inet6") if f in fams)
            if fams:
                out[str(iface)] = fams
        return out
    return {cfg.get("interface", "eth0"): ("inet", "inet6")}


def parse_zones(raw, what):
    """List (all auth) or mapping zone -> mode. Returns {zone: mode} in config order."""
    if raw is None:
        return {}
    if isinstance(raw, str):
        raw = [raw]
    if isinstance(raw, dict):
        items = raw.items()
    else:
        items = []
        for entry in raw:
            if isinstance(entry, dict):   # also accept a list of {zone: mode}
                items.extend(entry.items())
            else:
                items.append((entry, "auth"))
    out = {}
    for zone, mode in items:
        mode = str(mode or "auth").strip().lower()
        if mode not in ZONE_MODES:
            log.error("%s %s: unknown mode %r (expected auth or fallback)", what, zone, mode)
            sys.exit(1)
        out[norm(zone)] = mode
    return out


def load_config(path, connect=True):
    global config, client, zones, reverse_zones, ptr_zone, publish, aliases, snapshot

    try:
        with open(path) as f:
            config = yaml.safe_load(f) or {}
    except FileNotFoundError:
        log.error("Configuration file %s not found.", path)
        sys.exit(1)
    except yaml.YAMLError as e:
        log.error("Error parsing configuration file: %s", e)
        sys.exit(1)

    apply_config(config, connect=connect)


def apply_config(cfg, connect=True):
    global config, client, zones, reverse_zones, zone_modes, ptr_zone, publish, aliases, snapshot
    config = cfg

    if connect:
        lxd = config.get("lxd_client", {}) or {}
        cert = (lxd.get("cert_file"), lxd.get("key_file")) if lxd.get("cert_file") else None
        client = pylxd.Client(
            endpoint=lxd.get("endpoint"),
            cert=cert,
            verify=lxd.get("verify_cert", True),
            timeout=lxd.get("timeout", 1.5),
        )

    fwd = parse_zones(config.get("zones", config.get("domains", ["lxd"])), "zone")
    rev = parse_zones(config.get("reverse_zones"), "reverse zone")
    zone_modes = {**fwd, **rev}
    zones = sorted(fwd, key=len, reverse=True)
    reverse_zones = sorted(rev, key=len, reverse=True)
    # PTR targets default to the first forward zone as written in the config.
    ptr_zone = norm(config.get("ptr_zone") or next(iter(fwd), ""))
    publish = parse_publish(config)
    aliases = parse_aliases(config.get("aliases"))

    snapshot = Snapshot(
        max_age=float(config.get("cache_ttl", 10)),
        stale_age=float(config.get("stale_ttl", 300)),
    )


# --------------------------------------------------------------------------
# LXD data
# --------------------------------------------------------------------------

def is_slaac(ip):
    """True if the IPv6 address is EUI-64 based (contains ff:fe in the IID)."""
    try:
        return (int(ipaddress.IPv6Address(ip)) >> 24) & 0xFFFF == 0xFFFE
    except ValueError:
        return False


def pick_address(addresses, family):
    """
    First non-link-local address of the given family.
    For IPv6, non-SLAAC addresses win; a SLAAC address is the fallback.
    """
    slaac = None
    for a in addresses:
        if a.get("family") != family or a.get("scope") == "link":
            continue
        ip = a.get("address")
        if not ip:
            continue
        if family == "inet6" and is_slaac(ip):
            slaac = slaac or ip
            continue
        return ip
    return slaac


class Data:
    """One snapshot: {name: (v4 tuple, v6 tuple)} plus lazily built indexes."""

    def __init__(self, hosts):
        self.hosts = hosts
        self._ptr = None
        self._ents = None
        self._lock = threading.Lock()

    def ptr_index(self):
        if self._ptr is None:
            with self._lock:
                if self._ptr is None:
                    self._ptr = build_ptr_index(self.hosts)
        return self._ptr

    def ents(self):
        """
        Empty non-terminals: forward labels that are ancestors of a known label
        (glances for x.glances), and reverse names above a PTR.
        """
        if self._ents is None:
            with self._lock:
                if self._ents is None:
                    ents = set()
                    for label in list(self.hosts) + list(aliases):
                        parts = label.split(".")
                        ents.update(".".join(parts[i:]) for i in range(1, len(parts)))
                    ptr = self._ptr if self._ptr is not None else build_ptr_index(self.hosts)
                    for name in ptr:
                        parts = name.split(".")
                        ents.update(".".join(parts[i:]) for i in range(1, len(parts)))
                    self._ents = frozenset(ents)
        return self._ents


def reduce_instances(instances):
    """LXD instance list (recursion=2) -> {name: (v4 tuple, v6 tuple)}."""
    result = {}
    running = 0
    for inst in instances:
        name = norm(inst.get("name", ""))
        if not name:
            continue
        if (inst.get("status") or "").lower() != "running":
            result[name] = ((), ())
            continue
        network = (inst.get("state") or {}).get("network") or {}
        v4, v6 = [], []
        for iface, fams in publish.items():
            addrs = (network.get(iface) or {}).get("addresses") or []
            if "inet" in fams:
                a = pick_address(addrs, "inet")
                if a and a not in v4:
                    v4.append(a)
            if "inet6" in fams:
                a = pick_address(addrs, "inet6")
                if a and a not in v6:
                    v6.append(a)
        if v4 or v6:
            running += 1
        result[name] = (tuple(v4), tuple(v6))
    return result, running


def fetch_addresses():
    """One LXD call for all instances, including state."""
    params = {"recursion": 2}
    project = (config.get("lxd_client") or {}).get("project")
    if project:
        params["project"] = project
    resp = client.api.instances.get(params=params)
    instances = resp.json().get("metadata") or []
    result, running = reduce_instances(instances)
    if not result:
        log.warning("LXD returned no instances. Wrong project or endpoint?")
    elif not running:
        log.warning("%d instances but none has an address on %s. Check 'publish'.",
                    len(result), ", ".join(publish) or "-")
    log.debug("Snapshot refreshed: %d instances, %d with addresses", len(result), running)
    return Data(result)


class Snapshot:
    """Thread-safe, time-limited copy of fetch_addresses() with stale fallback."""

    def __init__(self, max_age, stale_age, fetch=None):
        self.max_age = max_age
        self.stale_age = stale_age
        self.fetch = fetch or fetch_addresses
        self._data = None
        self._fresh_until = 0.0
        self._stale_until = 0.0
        self._lock = threading.Lock()

    def get(self):
        if self._data is not None and time.monotonic() < self._fresh_until:
            return self._data

        with self._lock:
            now = time.monotonic()
            if self._data is not None and now < self._fresh_until:
                return self._data
            try:
                data = self.fetch()
            except Exception as e:
                if self._data is not None and now < self._stale_until:
                    self._fresh_until = now + self.max_age
                    log.warning("LXD refresh failed (%s); serving stale data", e)
                    return self._data
                log.error("LXD refresh failed and no usable data: %s", e)
                raise
            self._data = data
            self._fresh_until = now + self.max_age
            self._stale_until = now + self.stale_age
            return data


# --------------------------------------------------------------------------
# Name resolution
# --------------------------------------------------------------------------

def resolve(label, hosts, depth=0, seen=None):
    """
    Addresses for a label: (exists, [v4], [v6]).
    Instances win over aliases, at every level of alias expansion.
    """
    if label in hosts:
        v4, v6 = hosts[label]
        return True, list(v4), list(v6)

    alias = aliases.get(label)
    if alias is None:
        return False, [], []

    seen = (seen or frozenset()) | {label}
    v4, v6 = [], []

    def add(ip):
        target = v4 if ipaddress.ip_address(ip).version == 4 else v6
        if ip not in target:
            target.append(ip)

    for ip in alias.ips:
        add(str(ip))
    for name in alias.names:
        if name in seen or depth >= MAX_DEPTH:
            continue  # loops and deep nesting are reported once, at load time
        exists, a4, a6 = resolve(name, hosts, depth + 1, seen)
        if not exists:
            log.debug("Alias %s: target %s does not exist", label, name)
        for ip in a4 + a6:
            add(ip)
    for rx in alias.regexes:
        for n in sorted(hosts):
            if rx.search(n):
                for ip in hosts[n][0] + hosts[n][1]:
                    add(ip)
    return True, v4, v6


def build_ptr_index(hosts):
    """reverse_pointer -> PTR target, from instances, then literal-only aliases."""
    index = {}
    if not reverse_zones or not ptr_zone:
        return index
    for name in sorted(hosts):
        v4, v6 = hosts[name]
        for ip in v4 + v6:
            index.setdefault(ipaddress.ip_address(ip).reverse_pointer,
                             f"{name}.{ptr_zone}.")
    for label in sorted(aliases):
        alias = aliases[label]
        if label in hosts or not alias.literal_only:
            continue
        for ip in alias.ips:
            index.setdefault(ip.reverse_pointer, f"{label}.{ptr_zone}.")
    return index


# --------------------------------------------------------------------------
# DNS logic
# --------------------------------------------------------------------------

def split_qname(qname):
    """(zone, label, is_reverse) for a name we serve; label '' is the apex."""
    for group, rev in ((zones, False), (reverse_zones, True)):
        for z in group:
            if qname == z:
                return z, "", rev
            if qname.endswith("." + z):
                return z, qname[: -len(z) - 1], rev
    return None


def rr(qtype, qname, content, ttl):
    return {"qtype": qtype, "qname": qname, "content": content, "ttl": ttl, "auth": True}


def soa_record(zone, qname):
    soa = config.get("soa", {}) or {}
    primary_ns = soa.get("primary_ns", f"ns1.{zone}").rstrip(".") + "."
    admin = soa.get("admin_email", f"hostmaster.{zone}").replace("@", ".").rstrip(".") + "."
    content = " ".join(str(x) for x in (
        primary_ns,
        admin,
        int(time.time()),
        soa.get("refresh", 3600),
        soa.get("retry", 1800),
        soa.get("expire", 604800),
        soa.get("minimum", 60),
    ))
    return rr("SOA", qname, content, soa.get("ttl", 300))


class NotKnown(Exception):
    """A name in a fallback zone that this daemon has no data for."""


def lookup(qname, qtype):
    out_name = qname.rstrip(".") + "."
    q = norm(out_name)
    qtype = qtype.upper()

    match = split_qname(q)
    if match is None:
        return []
    zone, label, is_reverse = match

    if not label:
        return [soa_record(zone, out_name)] if qtype in ("SOA", "ANY") else []

    # PowerDNS probes NS/DS (delegations) and, without the zone cache, SOA at
    # every level. We serve no delegations; never SERVFAIL these.
    if qtype in STRUCTURAL_QTYPES:
        return []

    # Wildcard probes: we serve no wildcards.
    if label == "*" or label.startswith("*."):
        return []

    ttl = config.get("ttl", 300)
    fallback = zone_modes.get(zone) == "fallback"

    if is_reverse:
        data = snapshot.get()
        target = data.ptr_index().get(q)
        if not target:
            if q in data.ents():
                return []
            if fallback:
                raise NotKnown(q)
            return []
        return [rr("PTR", out_name, target, ttl)] if qtype in ("PTR", "ANY") else []

    health = norm(config.get("health_label", "_lxd-health"))
    if label == health or label.endswith("." + health):
        # dnsdist sends <random>.<health_label>.<zone> so no cache can answer.
        data = snapshot.get()  # raises (-> 503 -> SERVFAIL) without LXD data
        if qtype in ("TXT", "ANY"):
            return [rr("TXT", out_name, f'"ok {len(data.hosts)}"', 0)]
        return []

    data = snapshot.get()
    _, v4, v6 = resolve(label, data.hosts)
    if not (v4 or v6):
        if label in data.ents():
            return []
        # Unknown, stopped, or an alias that resolves to nothing right now.
        if fallback:
            raise NotKnown(q)
        return []

    answers = []
    if qtype in ("A", "ANY"):
        answers += [rr("A", out_name, ip, ttl) for ip in v4]
    if qtype in ("AAAA", "ANY"):
        answers += [rr("AAAA", out_name, ip, ttl) for ip in v6]
    return answers


def dump_zone(zone):
    """Text listing of what a zone serves right now (for diffing)."""
    zone = norm(zone)
    data = snapshot.get()
    lines = []
    ttl = config.get("ttl", 300)
    if zone in reverse_zones:
        for ptr, target in sorted(data.ptr_index().items()):
            if ptr == zone or ptr.endswith("." + zone):
                lines.append(f"{ptr}.\t{ttl}\tIN\tPTR\t{target}")
        return lines
    if zone not in zones:
        raise SystemExit(f"{zone} is not a configured zone")
    labels = sorted(set(data.hosts) | set(aliases))
    for label in labels:
        _, v4, v6 = resolve(label, data.hosts)
        for ip in v4:
            lines.append(f"{label}.{zone}.\t{ttl}\tIN\tA\t{ip}")
        for ip in v6:
            lines.append(f"{label}.{zone}.\t{ttl}\tIN\tAAAA\t{ip}")
    return lines


# --------------------------------------------------------------------------
# HTTP endpoints (PowerDNS remote backend, HTTP connector, RESTful mode)
# --------------------------------------------------------------------------

@app.middleware("http")
async def collapse_slashes(request, call_next):
    # A remote-connection-string url with a trailing slash makes PowerDNS
    # request //lookup/...; accept both forms.
    path = request.scope.get("path", "")
    if "//" in path:
        request.scope["path"] = re.sub("/{2,}", "/", path)
    return await call_next(request)


@app.get("/lookup/{qname:path}/{qtype}")
def lookup_endpoint(qname: str, qtype: str):
    try:
        result = lookup(qname, qtype)
    except NotKnown:
        # Fallback zone, unknown name: PowerDNS answers SERVFAIL.
        log.debug("lookup %s %s -> unknown in fallback zone", qname, qtype)
        raise HTTPException(status_code=503, detail="not known to the fallback")
    except Exception as e:
        log.debug("lookup %s %s failed: %s", qname, qtype, e)
        raise HTTPException(status_code=503, detail="LXD unavailable")
    log.debug("lookup %s %s -> %d records", qname, qtype, len(result))
    return {"result": result}


def domain_info(i, zone):
    return {"id": i + 1, "zone": zone + ".", "kind": "native", "serial": int(time.time()),
            "masters": [], "notified_serial": 0, "last_check": 0}


def all_zones():
    return zones + reverse_zones


@app.get("/getAllDomains")
@app.get("/getAllDomains/{include_disabled}")
def get_all_domains(include_disabled: str = ""):
    return {"result": [domain_info(i, z) for i, z in enumerate(all_zones())]}


@app.get("/getDomainInfo/{qname:path}")
def get_domain_info(qname: str):
    q = norm(qname)
    for i, z in enumerate(all_zones()):
        if z == q:
            return {"result": domain_info(i, z)}
    return {"result": False}


@app.get("/getAllDomainMetadata/{qname:path}")
def get_all_domain_metadata(qname: str):
    return {"result": []}


@app.get("/getDomainMetadata/{qname:path}/{kind}")
def get_domain_metadata(qname: str, kind: str):
    return {"result": []}


# Not used by PowerDNS: shows what the daemon currently knows.
#   curl -s 'http://[::1]:8053/status' | jq
@app.get("/status")
def status():
    try:
        data = snapshot.get()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"LXD unavailable: {e}")
    shadowed = sorted(a for a in aliases if a in data.hosts)
    resolved = {}
    for label in sorted(aliases):
        _, v4, v6 = resolve(label, data.hosts)
        resolved[label] = {"ipv4": v4, "ipv6": v6}
    return {
        "zones": {z: zone_modes[z] for z in zones},
        "reverse_zones": {z: zone_modes[z] for z in reverse_zones},
        "ptr_zone": ptr_zone,
        "publish": {k: list(v) for k, v in publish.items()},
        "instances": {n: {"ipv4": list(v4), "ipv6": list(v6)}
                      for n, (v4, v6) in sorted(data.hosts.items())},
        "aliases": resolved,
        "aliases_shadowed_by_instances": shadowed,
    }


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="LXD DNS lookup service")
    parser.add_argument("-c", "--config", default="/etc/lxd_nslookup.yml",
                        help="Configuration file path (default: /etc/lxd_nslookup.yml)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--dump", metavar="ZONE",
                        help="Print the zone as currently served and exit")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    load_config(args.config)

    if args.dump:
        print("\n".join(dump_zone(args.dump)))
        return

    import uvicorn

    server = config.get("server", {}) or {}
    host = server.get("host", "127.0.0.1")
    port = server.get("port", 8081)

    try:
        data = snapshot.get()
        log.info("LXD: %d instances, %d with published addresses", len(data.hosts),
                 sum(1 for v4, v6 in data.hosts.values() if v4 or v6))
    except Exception as e:
        log.warning("Initial LXD fetch failed (%s); will retry on first query", e)

    for label in aliases:
        if data_has(label):
            log.warning("Alias %r is shadowed by an instance of the same name", label)

    log.info("Starting LXD DNS lookup service on %s:%s (zones: %s)", host, port,
             ", ".join(f"{z} ({zone_modes[z]})" for z in all_zones()))
    uvicorn.run(app, host=host, port=port, access_log=args.debug,
                log_level="debug" if args.debug else "info")


def data_has(label):
    try:
        return label in snapshot.get().hosts
    except Exception:
        return False


if __name__ == "__main__":
    main()
