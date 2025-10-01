# LXD NSLookup

A DNS lookup service for LXD containers that provides dynamic DNS resolution for container names.

## Configuration

The script uses a YAML configuration file to specify LXD client settings, domain suffixes, and network interface settings.

### Command Line Options

- `-c, --config CONFIG_FILE`: Specify the configuration file path (default: `/etc/lxd_nslookup.yml`)

### Configuration File Format

See `lxd_nslookup.yml.example` for a complete example configuration file.

```yaml
# LXD client configuration
lxd_client:
  endpoint: "https://[fdf6:e23f:8e51:72f1::1]:8443"
  cert_file: "/path/to/client.crt"
  key_file: "/path/to/client.key"
  verify_cert: "/path/to/servercerts/server.crt"

# Domain suffixes to match against
domain_suffixes:
  - ".lxd.mydomain"
  - ".lxc.local"

# Network interface to scan for container IP addresses
interface: "eth0"
```

### Configuration Keys

- `lxd_client`: LXD client connection settings
  - `endpoint`: LXD server endpoint URL
  - `cert_file`: Path to client certificate file
  - `key_file`: Path to client key file
  - `verify_cert`: Path to server certificate file for verification
- `domains`: List of domain suffixes that the service will respond to
- `interface`: Network interface name to scan for container IP addresses

## Usage

### Running the DNS Service

```bash
# Using default configuration file (/etc/lxd_nslookup.yml)
python3 lxd_nslookup.py

# Using custom configuration file
python3 lxd_nslookup.py -c /path/to/custom_config.yml
```

## Installation

1. Copy the example configuration file:
   ```bash
   sudo cp lxd_nslookup.yml.example /etc/lxd_nslookup.yml
   ```

2. Edit the configuration file with your LXD settings:
   ```bash
   sudo nano /etc/lxd_nslookup.yml
   ```

3. Install dependencies:
   ```bash
   poetry install
   ```

4. Run the service:
   ```bash
   poetry run python3 lxd_nslookup.py
   ```
