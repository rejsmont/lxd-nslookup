#!/usr/bin/env python3
"""
LXD -> PowerDNS remote backend (HTTP connector).

Resolves <container>.<domain> to the container's IPv4/IPv6 addresses.

Design:
  * One LXD API call (GET /1.0/containers?recursion=2) returns every container
    with its state. The result is reduced to {name: (ipv4, ipv6)} and kept as a
    snapshot for `cache_ttl` seconds. Every lookup is then a dict lookup, and
    LXD load is bounded to one call per `cache_ttl`, whatever the query mix.
  * If LXD stops responding, the last good snapshot is served for up to
    `stale_ttl` seconds. After that, lookups fail with HTTP 503, which makes
    PowerDNS answer SERVFAIL rather than a (negatively cached) NXDOMAIN.
  * The SOA is returned only at the zone apex, so PowerDNS sees one zone per
    configured domain and nonexistent names get a proper NXDOMAIN.
  * /getAllDomains returns the configured domains, so the PowerDNS zone cache
    (zone-cache-refresh-interval > 0) works and PowerDNS stops probing
    "<name> SOA" up the tree on every cache miss.
  * Handlers are synchronous, so FastAPI runs them in its thread pool and a
    slow LXD call never blocks the event loop.

Configuration (YAML):
  lxd_client:                    # omit endpoint to use the local unix socket
    endpoint: https://...        # LXD API endpoint
    cert_file: /path/client.crt
    key_file: /path/client.key
    verify_cert: true            # or path to the server certificate
    timeout: 1.5                 # seconds; keep below the PowerDNS remote timeout
    project: default             # LXD project holding the containers
  server:
    host: "::1"
    port: 8053
  domains: [lxd]
  interface: eth0                # interface whose addresses are published
  ttl: 300                       # A/AAAA record TTL
  cache_ttl: 10                  # snapshot lifetime
  stale_ttl: 300                 # how long to serve stale data if LXD is down
  aliases:                       # optional
    web: [web1, web2]            # explicit list of containers
    db: "^db-"                   # regex matched against container names
  soa:
    primary_ns: ns1.lxd
    admin_email: admin@lxd
    ttl: 300
    minimum: 60                  # negative-caching TTL used by resolvers
    refresh: 3600
    retry: 1800
    expire: 604800
"""
import argparse
import ipaddress
import logging
import re
import sys
import threading
import time
import warnings

import pylxd
import urllib3
import uvicorn
import yaml
from fastapi import FastAPI, HTTPException

warnings.filterwarnings("ignore", category=UserWarning, module="pylxd.models._model")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("lxd_nslookupd")
app = FastAPI()

config = {}
client = None
domains = []     # normalised, longest first
aliases = {}     # label -> frozenset of names | compiled regex
snapshot = None  # Snapshot instance


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def load_config(path):
    global config, client, domains, aliases, snapshot

    try:
        with open(path) as f:
            config = yaml.safe_load(f) or {}
    except FileNotFoundError:
        log.error("Configuration file %s not found.", path)
        sys.exit(1)
    except yaml.YAMLError as e:
        log.error("Error parsing configuration file: %s", e)
        sys.exit(1)

    lxd = config.get("lxd_client", {})
    client = pylxd.Client(
        endpoint=lxd.get("endpoint"),
        cert=(lxd.get("cert_file"), lxd.get("key_file")),
        verify=lxd.get("verify_cert", True),
        timeout=lxd.get("timeout", 1.5),
    )

    domains = sorted(
        {d.strip(".").lower() for d in config.get("domains", ["lxd"])},
        key=len,
        reverse=True,
    )

    aliases = {}
    for label, target in (config.get("aliases") or {}).items():
        label = str(label).lower()
        if isinstance(target, list):
            aliases[label] = frozenset(str(n).lower() for n in target)
        elif isinstance(target, str):
            try:
                aliases[label] = re.compile(target)
            except re.error as e:
                log.warning("Ignoring alias %r: invalid regex %r (%s)", label, target, e)
        else:
            log.warning("Ignoring alias %r: expected list or regex string", label)

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


def fetch_addresses():
    """
    One LXD call for all containers, including state.
    Returns {name: (ipv4 | None, ipv6 | None)}. Stopped containers are included
    with (None, None) so they still take precedence over aliases.
    """
    params = {"recursion": 2}
    project = config.get("lxd_client", {}).get("project")
    if project:
        params["project"] = project
    resp = client.api.instances.get(params=params)
    instances = resp.json().get("metadata") or []
    iface = config.get("interface", "eth0")

    result = {}
    for inst in instances:
        if inst.get("type", "container") != "container":
            continue
        name = inst.get("name", "").lower()
        if not name:
            continue
        if (inst.get("status") or "").lower() != "running":
            result[name] = (None, None)
            continue
        network = (inst.get("state") or {}).get("network") or {}
        addrs = (network.get(iface) or {}).get("addresses") or []
        result[name] = (pick_address(addrs, "inet"), pick_address(addrs, "inet6"))

    running = sum(1 for v4, v6 in result.values() if v4 or v6)
    if not result:
        log.warning("LXD returned no containers (project: %s). Wrong project or endpoint?",
                    project or "default")
    elif not running:
        log.warning("%d containers but none has an address on '%s'. Wrong 'interface'?",
                    len(result), iface)
    log.debug("Snapshot refreshed: %d containers, %d with addresses", len(result), running)
    return result


class Snapshot:
    """Thread-safe, time-limited copy of fetch_addresses() with stale fallback."""

    def __init__(self, max_age, stale_age):
        self.max_age = max_age
        self.stale_age = stale_age
        self._data = None
        self._fresh_until = 0.0
        self._stale_until = 0.0
        self._lock = threading.Lock()

    def get(self):
        if self._data is not None and time.monotonic() < self._fresh_until:
            return self._data

        with self._lock:
            now = time.monotonic()
            # Another thread may have refreshed while we waited for the lock.
            if self._data is not None and now < self._fresh_until:
                return self._data
            try:
                data = fetch_addresses()
            except Exception as e:
                if self._data is not None and now < self._stale_until:
                    # Serve stale data; retry no sooner than max_age from now.
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
# DNS logic
# --------------------------------------------------------------------------

def split_qname(qname):
    """(zone, label) for a name under one of our domains; label '' is the apex."""
    for d in domains:
        if qname == d:
            return d, ""
        if qname.endswith("." + d):
            return d, qname[: -len(d) - 1]
    return None


def rr(qtype, qname, content, ttl):
    return {"qtype": qtype, "qname": qname, "content": content, "ttl": ttl, "auth": True}


def soa_record(zone, qname):
    soa = config.get("soa", {})
    primary_ns = soa.get("primary_ns", f"ns1.{zone}").rstrip(".") + "."
    admin = soa.get("admin_email", f"admin.{zone}").replace("@", ".").rstrip(".") + "."
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


def lookup(qname, qtype):
    out_name = qname.rstrip(".") + "."
    q = out_name[:-1].lower()
    qtype = qtype.upper()

    match = split_qname(q)
    if match is None:
        return []
    zone, label = match

    # Zone apex: SOA only.
    if not label:
        return [soa_record(zone, out_name)] if qtype in ("SOA", "ANY") else []

    if qtype not in ("A", "AAAA", "ANY"):
        return []

    data = snapshot.get()

    if label in data:
        names = [label]
    else:
        alias = aliases.get(label)
        if alias is None:
            return []
        if isinstance(alias, re.Pattern):
            names = sorted(n for n in data if alias.search(n))
        else:
            names = sorted(n for n in alias if n in data)

    ttl = config.get("ttl", 300)
    answers = []
    for n in names:
        v4, v6 = data[n]
        if v4 and qtype in ("A", "ANY"):
            answers.append(rr("A", out_name, v4, ttl))
        if v6 and qtype in ("AAAA", "ANY"):
            answers.append(rr("AAAA", out_name, v6, ttl))
    return answers


# --------------------------------------------------------------------------
# HTTP endpoints (PowerDNS remote backend, HTTP connector, RESTful mode)
# --------------------------------------------------------------------------

@app.get("/lookup/{qname:path}/{qtype}")
def lookup_endpoint(qname: str, qtype: str):
    try:
        result = lookup(qname, qtype)
    except Exception:
        # PowerDNS turns a failed backend call into SERVFAIL, which resolvers
        # don't cache the way they cache NXDOMAIN.
        raise HTTPException(status_code=503, detail="LXD unavailable")
    log.debug("lookup %s %s -> %d records", qname, qtype, len(result))
    return {"result": result}


def domain_info(zone, zone_id):
    return {
        "id": zone_id,
        "zone": zone + ".",
        "kind": "native",
        "serial": int(time.time()),
        "notified_serial": 0,
        "last_check": 0,
        "masters": [],
    }


# Zone list for the PowerDNS zone cache (zone-cache-refresh-interval > 0).
# With it, PowerDNS knows the zones up front and stops probing
# "<name> SOA" for every query to work out which zone a name belongs to.
# Two routes, because the connector may pass include_disabled as a query
# parameter or as a path segment depending on the PowerDNS version.
@app.get("/getAllDomains")
@app.get("/getAllDomains/{rest:path}")
def get_all_domains(rest: str = ""):
    return {"result": [domain_info(z, i) for i, z in enumerate(domains, start=1)]}


@app.get("/getDomainInfo/{qname:path}")
def get_domain_info(qname: str):
    q = qname.rstrip(".").lower()
    for i, z in enumerate(domains, start=1):
        if z == q:
            return {"result": domain_info(z, i)}
    return {"result": False}


@app.get("/getAllDomainMetadata/{qname:path}")
def get_all_domain_metadata(qname: str):
    return {"result": []}



# Not used by PowerDNS: shows what the daemon currently knows.
#   curl -s 'http://[::1]:8053/status' | jq
@app.get("/status")
def status():
    try:
        data = snapshot.get()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"LXD unavailable: {e}")
    return {
        "domains": domains,
        "interface": config.get("interface", "eth0"),
        "project": config.get("lxd_client", {}).get("project") or "default",
        "containers": {n: {"ipv4": v4, "ipv6": v6} for n, (v4, v6) in sorted(data.items())},
    }


@app.get("/getDomainMetadata/{qname:path}/{kind}")
def get_domain_metadata(qname: str, kind: str):
    return {"result": []}


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="LXD DNS lookup service")
    parser.add_argument("-c", "--config", default="/etc/lxd_nslookup.yml",
                        help="Configuration file path (default: /etc/lxd_nslookup.yml)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    load_config(args.config)

    server = config.get("server", {})
    host = server.get("host", "127.0.0.1")
    port = server.get("port", 8081)

    # Warm the snapshot so the first queries don't wait on LXD.
    try:
        data = snapshot.get()
        log.info("LXD: %d containers, %d with an address on '%s'", len(data),
                 sum(1 for v4, v6 in data.values() if v4 or v6),
                 config.get("interface", "eth0"))
    except Exception as e:
        log.warning("Initial LXD fetch failed (%s); will retry on first query", e)

    log.info("Starting LXD DNS lookup service on %s:%s (domains: %s)",
             host, port, ", ".join(domains))
    uvicorn.run(app, host=host, port=port, access_log=args.debug,
                log_level="debug" if args.debug else "info")


if __name__ == "__main__":
    main()
