#!/usr/bin/env python3

import os
import sys
import json
import logging
from time import sleep
import requests
import pylxd
import yaml
import netaddr

from pathlib import Path


logging.basicConfig(
    level=logging.INFO,
    format='%(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('kea-pdns-hook')


class LXDClient:
    def __init__(self, endpoint, cert=None, key=None):
        try:
            self.client = pylxd.Client(
                endpoint=endpoint,
                cert=(cert, key),
                verify=True
            )
        except Exception as e:
            logger.error(f"Error initializing LXD client: {e}")
            self.client = None

    def find_container_by_ip(self, ip: str):
        if not self.client:
            return None, None
        try:
            ip = netaddr.IPAddress(ip)
            for container in self.client.containers.all():
                state = container.state()
                for iface in state.network.values():
                    addresses = [netaddr.IPAddress(a.get('address')) for a in iface.get('addresses', [])]
                    if addresses and ip in addresses:
                        return container, iface
            logger.info(f"No container found with address {ip}")
            return None, None
        except Exception as e:
            logger.error(f"Error querying LXD: {e}")
            return None, None
    

class KeaClient:
    def __init__(self, api_url, api_user=None, api_key=None):
        self.api_url = api_url.rstrip('/')
        self.api_user = api_user
        self.api_key = api_key

    def _send(self, command, args):
        headers = {'Content-Type': 'application/json'}
        payload = {
            "command": command,
            "service": ["dhcp6"],
            "arguments": args
        }
        try:
            for i in range(3):
                resp = requests.post(self.api_url, auth=(self.api_user, self.api_key), headers=headers, json=payload, timeout=10)
                if resp.status_code == 200:
                    return resp.json()[0]
                if resp.status_code == 503:
                    sleep(1)
                    continue
            else:
                return {"result": 1, "text": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"result": 1, "text": str(e)}

    def reservation_exists(self, ip_address, duid):
        reservations = self._send("reservation-get-by-address", {"ip-address": str(ip_address)})
        for host in reservations.get('arguments', {}).get('hosts', []):
            if host.get('duid') == duid:
                return True
        return False

    def create_reservation(self, subnet_id, duid, ip_address, hostname=None):
        args = {
            "subnet-id": subnet_id,
            "duid": duid,
            "ip-addresses": [str(ip_address)]
        }
        if hostname:
            args["hostname"] = hostname
        return self._send("reservation-add", {"reservation": args})["result"] == 0
    
    def get_subnet_id_by_prefix(self, prefix: netaddr.IPNetwork):
        resp = self._send("subnet6-list", {})
        if resp.get('result') != 0:
            return False
        for subnet in resp.get('arguments', {}).get('subnets', []):
            subnet_prefix = netaddr.IPNetwork(subnet.get('subnet', '::/0'))
            print(subnet_prefix, prefix)
            if subnet_prefix == prefix:
                return subnet.get('id')
        return None


class PowerDNSClient:
    def __init__(self, api_url, api_key, server_id='localhost'):
        self.api_url = api_url.rstrip('/')
        self.headers = {
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        }
        self.server_id = server_id

    def add_aaaa_record(self, zone, name, address):
        if not name.endswith('.'):
            name += '.'
        if not zone.endswith('.'):
            zone += '.'
        data = {
            "rrsets": [{
                "name": name,
                "type": "AAAA",
                "changetype": "REPLACE",
                "records": [{"content": str(address), "disabled": False}],
                "ttl": 3600
            }]
        }
        url = f"{self.api_url}/zones/{zone}"
        for i in range(3):
            resp = requests.patch(url, headers=self.headers, json=data, timeout=10)
            if resp.status_code == 204:
                return True
            if resp.status_code == 503:
                sleep(1)
        return False

    def add_ptr_record(self, zone, ptr_name, fqdn):
        if not ptr_name.endswith('.'):
            ptr_name += '.'
        if not zone.endswith('.'):
            zone += '.'
        if not fqdn.endswith('.'):
            fqdn += '.'
        data = {
            "rrsets": [{
                "name": ptr_name,
                "type": "PTR",
                "changetype": "REPLACE",
                "records": [{"content": fqdn, "disabled": False}],
                "ttl": 3600
            }]
        }
        url = f"{self.api_url}/zones/{zone}"
        for i in range(3):
            resp = requests.patch(url, headers=self.headers, json=data, timeout=10)
            if resp.status_code == 204:
                return True
            if resp.status_code == 503:
                sleep(1)
        return False

    def delete_aaaa_record(self, zone, name):
        if not name.endswith('.'):
            name += '.'
        if not zone.endswith('.'):
            zone += '.'
        data = {"rrsets": [{"name": name, "type": "AAAA", "changetype": "DELETE"}]}
        url = f"{self.api_url}/zones/{zone}"
        for i in range(3):
            resp = requests.patch(url, headers=self.headers, json=data, timeout=10)
            if resp.status_code == 204:
                return True
            if resp.status_code == 503:
                sleep(1)
        return False

    def delete_ptr_record(self, zone, ptr_name):
        if not ptr_name.endswith('.'):
            ptr_name += '.'
        if not zone.endswith('.'):
            zone += '.'
        data = {"rrsets": [{"name": ptr_name, "type": "PTR", "changetype": "DELETE"}]}
        url = f"{self.api_url}/zones/{zone}"
        for i in range(3):
            resp = requests.patch(url, headers=self.headers, json=data, timeout=10)
            if resp.status_code == 204:
                return True
            if resp.status_code == 503:
                sleep(1)
        return False


def load_config(config_file: str = "/etc/kea/pdns_hook.yml") -> dict:
    """Load YAML configuration and merge with sensible defaults.
    """
    try:
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Configuration file {config_file} not found.")
        return {}
    except yaml.YAMLError as e:
        print(f"Error parsing configuration file: {e}")
        return {}

def get_container_netcfg(lxd, subnet_prefix, client_addr):
    for _ in range(5):
        container, iface = lxd.find_container_by_ip(client_addr)
        if not container:
            sys.exit(1)
        mac_addr = netaddr.EUI(iface.get('hwaddr'))
        addresses = [netaddr.IPAddress(a.get('address')) for a in iface.get('addresses', []) if a.get('family') == 'inet6']
        slaac_addr = mac_addr.ipv6(subnet_prefix.network)
        if slaac_addr in addresses:
            break
        sleep(1)
    else:
        return None, None, None, None
    return container, mac_addr, slaac_addr, addresses

def get_subnet_prefix(config, interface):
    return netaddr.IPNetwork(config.get('interfaces', {}).get(interface))

# Main logic for explicit hook point
def main():
    # Collect environment variables set by kea's run_script
    hook_point = sys.argv[1] if len(sys.argv) > 1 else None
    query_type = os.environ.get("QUERY6_TYPE")
    interface = os.environ.get("QUERY6_IFACE_NAME")
    client_addr = os.environ.get("QUERY6_REMOTE_ADDR")
    hostname = os.environ.get("LEASE6_HOSTNAME")
    lease_address = os.environ.get("LEASE6_ADDRESS")
    duid = os.environ.get("QUERY6_DUID") or os.environ.get("QUERY6_CLIENT_ID")

    if not hook_point:
        sys.exit(0)

    # Load hierarchical config
    config = load_config()

    # Configure logging level from config
    try:
        level = getattr(logging, config.get('log_level', 'INFO').upper(), logging.INFO)
        logger.setLevel(level)
    except Exception:
        logger.setLevel(logging.INFO)

    if not hook_point in ["leases6_committed", "lease6_release"]:
        sys.exit(0)

    if interface not in config.get('interfaces', {}):
        sys.exit(0)

    # Initialize clients from config
    lxd_cfg = config.get('lxd', {})
    lxd_endpoint = lxd_cfg.get('endpoint')
    lxd_cert = lxd_cfg.get('cert')
    lxd_key = lxd_cfg.get('key')
    lxd = LXDClient(lxd_endpoint, cert=lxd_cert, key=lxd_key)

    kea_cfg = config.get('kea', {})
    kea = KeaClient(kea_cfg.get('api_url'), kea_cfg.get('api_user'), kea_cfg.get('api_key'))

    pdns_cfg = config.get('pdns', {})
    pdns = PowerDNSClient(pdns_cfg.get('api_url'), pdns_cfg.get('api_key'), pdns_cfg.get('server_id'))

    # Zones
    zones = config.get('zones', {})
    forward_zone = zones.get('forward')
    reverse_zone = zones.get('reverse')

    # Process based on hook point
    if hook_point == "leases6_committed":
        subnet_prefix = get_subnet_prefix(config, interface)
        container, mac_addr, slaac_addr, addresses = get_container_netcfg(lxd, subnet_prefix, client_addr)
        if not container:
            sys.exit(1)
        hostname = str(container.name).strip('.') if container else None
        if not hostname:
            sys.exit(1)
        if query_type == "REQUEST" and not kea.reservation_exists(slaac_addr, duid):
            subnet_id = kea.get_subnet_id_by_prefix(subnet_prefix)
            if kea.create_reservation(subnet_id, duid, slaac_addr, container.name):
                logger.info(f"Created reservation for {hostname} -> {slaac_addr} with DUID {duid} / MAC {mac_addr}")
        fqdn = f"{hostname}.{forward_zone.strip('.')}"
        if pdns.add_aaaa_record(forward_zone, fqdn, slaac_addr):
            logger.info(f"Added AAAA record for {fqdn} -> {slaac_addr}")
        if pdns.add_ptr_record(reverse_zone, slaac_addr.reverse_dns, fqdn):
            logger.info(f"Added PTR record for {slaac_addr.reverse_dns} -> {fqdn}")
    elif hook_point == "lease6_release" and hostname and lease_address:
        fqdn = f"{hostname.strip('.')}.{forward_zone.strip('.')}"
        address = netaddr.IPAddress(lease_address)
        if pdns.delete_aaaa_record(forward_zone, fqdn):
            logger.info(f"Deleted AAAA record for {fqdn}")
        ptr_name = address.reverse_dns
        if pdns.delete_ptr_record(reverse_zone, ptr_name):
            logger.info(f"Deleted PTR record for {ptr_name}")

if __name__ == "__main__":
    main()
