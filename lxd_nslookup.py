#!/usr/bin/env python3
import ipaddress
import argparse
import sys
import yaml
from datetime import datetime
from fastapi import FastAPI, Request
import uvicorn
import pylxd
import urllib.parse
import json

app = FastAPI()
config = {}
client = None

def load_config(config_file):
    """
    Load and validate configuration from a YAML file and initialize LXD client.
    
    This function reads the YAML configuration file, validates the structure,
    and initializes the global LXD client connection using the provided settings.
    
    Args:
        config_file (str): Path to the YAML configuration file

    Expected Configuration Structure:
        lxd_client:
            endpoint: LXD server endpoint URL
            cert_file: Path to client certificate file
            key_file: Path to client key file
            verify_cert: Path to server certificate or boolean for verification
        server:
            host: IP address to bind the server to (default: 127.0.0.1)
            port: Port number to bind the server to (default: 8081)
        domains:
            - List of domain suffixes to handle (default: ['lxd'])
        soa:
            primary_ns: Primary nameserver for SOA record (default: ns1.{domain})
            admin_email: Admin email for SOA record (default: admin.{domain})
            serial: Auto-generated from current Unix timestamp
            refresh: Refresh interval in seconds (default: 3600)
            retry: Retry interval in seconds (default: 1800)
            expire: Expire time in seconds (default: 604800)
            minimum: Minimum TTL in seconds (default: 86400)
    """
    global config, client
    
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Configuration file {config_file} not found.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing configuration file: {e}")
        sys.exit(1)
    
    lxd_config = config.get('lxd_client', {})
    client = pylxd.Client(
        endpoint=lxd_config.get('endpoint'),
        cert=(lxd_config.get('cert_file'), lxd_config.get('key_file')),
        verify=lxd_config.get('verify_cert', True)
    )

def is_slaac(ip):
    """
    Check if the given IPv6 address is a SLAAC (Stateless Address Autoconfiguration) address.
    
    SLAAC addresses are automatically generated IPv6 addresses that contain the MAC address
    of the network interface. They can be identified by the presence of 'fffe' in the
    interface identifier portion of the address (bits 104-119).
    
    Args:
        ip (str): IPv6 address string to check
    
    Returns:
        bool: True if the address is a SLAAC address, False otherwise
    """
    try:
        addr = int(ipaddress.IPv6Address(ip))
        shifted = addr >> (128 - 104)   # shift right by 24
        return (shifted & 0xFFFF) == 0xfffe
    except ValueError:
        return False

def get_container_ip(container_name, interface=None, family='inet'):
    """
    Get the IP address of a running LXD container on a specific network interface.
    
    This function retrieves the IP address for a container from the specified network
    interface. For IPv6 addresses, it prioritizes non-SLAAC addresses but will fall
    back to SLAAC addresses if no other IPv6 addresses are available.
    
    Args:
        container_name (str): Name of the LXD container to query
        interface (str, optional): Network interface name to check for addresses.
                                 Defaults to the interface specified in config, or 'eth0'
        family (str): Address family to filter by. Either 'inet' for IPv4 or 
                     'inet6' for IPv6. Defaults to 'inet'
    
    Returns:
        str or None: The IP address string if found, None if container is not running
                    or no matching address is found
    
    Raises:
        pylxd.exceptions.NotFound: If the container does not exist
        pylxd.exceptions.LXDAPIException: If there's an error communicating with LXD
    
    Note:
        - Only returns addresses with scope != 'link' (excludes link-local addresses)
        - For IPv6, prefers non-SLAAC addresses over SLAAC addresses
        - Container must be in 'running' state to return an IP address
    """
    if interface is None:
        interface = config.get('interface', 'eth0')
    
    try:
        container = client.containers.get(container_name)
    except pylxd.exceptions.NotFound:
        return None
    if not container.status.lower() == "running":
        return None

    slaac = None
    for addr in container.state().network.get(interface, {}).get("addresses", []):
        if addr.get("family") != family:
            continue
        if addr.get("scope") == "link":
            continue
        ip = addr.get("address")
        if family == 'inet6' and is_slaac(ip):
            slaac = ip
        return ip
    
    if slaac is not None:
        return slaac
    
    return None


@app.post("/lookup")
async def lookup(request: Request):
    """
    FastAPI endpoint for DNS lookup requests for LXD containers.
    
    This endpoint handles DNS queries for container names, returning appropriate
    A (IPv4), AAAA (IPv6), or SOA (Start of Authority) records based on the query type 
    and configured domain suffixes.
    
    Args:
        request (Request): FastAPI request object containing form data or JSON payload
    
    Returns:
        list: List of DNS answer dictionaries, each containing:
            - qtype (str): Query type ('A', 'AAAA', or 'SOA')
            - qname (str): Queried domain name
            - content (str): IP address or SOA record content
            - ttl (int): Time to live in seconds
            - auth (bool): Authoritative response flag
    """
    
    body = await request.body()
    
    # Try to parse as form data first (PowerDNS format)
    try:
        body_str = body.decode('utf-8')
        if body_str.startswith('parameters='):
            # Parse URL-encoded form data
            parsed_data = urllib.parse.parse_qs(body_str)
            parameters_json = parsed_data['parameters'][0]
            data = json.loads(parameters_json)
            print(f"Parsed form data: {data}")
        else:
            # Try to parse as JSON
            data = json.loads(body_str)
            print(f"Parsed JSON data: {data}")
    except (json.JSONDecodeError, KeyError, UnicodeDecodeError) as e:
        print(f"Error parsing request body: {e}")
        return []
    
    qname = data.get("qname", "").rstrip(".")
    qtype = data.get("qtype", "A")

    if qtype == "SOA":
        for domain in config.get('domains', ['lxd']):
            if qname == domain or qname.endswith('.' + domain):
                soa_config = config.get('soa', {})
                primary_ns = soa_config.get('primary_ns', f'ns1.{domain}')
                admin_email = soa_config.get('admin_email', f'admin.{domain}')
                serial = str(int(datetime.now().timestamp()))
                refresh = soa_config.get('refresh', 3600)
                retry = soa_config.get('retry', 1800)
                expire = soa_config.get('expire', 604800)
                minimum = soa_config.get('minimum', 86400)
                
                soa_content = f"{primary_ns} {admin_email} {serial} {refresh} {retry} {expire} {minimum}"
                
                response = [{
                    "qtype": "SOA",
                    "qname": qname,
                    "content": soa_content,
                    "ttl": 86400,
                    "auth": True
                }]

                print(f"Returning SOA record: {response}")
                return response
        
        print(f"No matching domain for SOA query: {qname}")
        return []

    cname = None
    for suffix in config.get('domains', ['lxd']):
        if qname.endswith(suffix):
            cname = qname[:-len(suffix)].rstrip(".")
            break
    
    if cname is None:
        return []
    
    ipv4, ipv6 = None, None
    answers = []

    if qtype == "A" and (ipv4 := get_container_ip(cname, family='inet')):
        answers.append({
            "qtype": "A",
            "qname": qname,
            "content": ipv4,
            "ttl": 60,
            "auth": True
        })
    elif qtype == "AAAA" and (ipv6 := get_container_ip(cname, family='inet6')):
        answers.append({
            "qtype": "AAAA",
            "qname": qname,
            "content": ipv6,
            "ttl": 60,
            "auth": True
        })

    print(f"Returning answers: {answers}")
    return answers


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='LXD DNS lookup service')
    parser.add_argument('-c', '--config', 
                       default='/etc/lxd_nslookup.yml',
                       help='Configuration file path (default: /etc/lxd_nslookup.yml)')
    
    args = parser.parse_args()
    
    load_config(args.config)
    
    # Get server configuration with defaults
    server_config = config.get('server', {})
    host = server_config.get('host', '127.0.0.1')
    port = server_config.get('port', 8081)
    
    print(f"Starting server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
