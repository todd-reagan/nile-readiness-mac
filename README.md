# Nile Readiness Test (NRT)

This tool helps test network connectivity and features required for Nile Connect on macOS.

## Features

- Network interface configuration
- Loopback interface creation for subnet testing
- Static route configuration
- OSPF Hello packet detection
- Comprehensive connectivity testing:
  - DNS resolution
  - DHCP relay functionality (optional)
  - RADIUS authentication (optional)
  - NTP synchronization
  - HTTPS connectivity
  - SSL certificate validation
  - UDP connectivity testing

## Requirements

- macOS
- Python 3.6+
- Scapy (for packet sniffing)
- Root/sudo privileges (for network operations)

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/nile-readiness-test.git
    cd nile-readiness-test
    ```

2.  **Install System Utilities (using Homebrew):**
    The script requires several command-line utilities. You can install them using Homebrew:
    ```bash
    brew install dnsmasq curl netcat openssl
    ```
    *   `dnsmasq` provides `dig`.
    *   `curl`, `netcat`, and `openssl` are also essential.

3.  **Install Python Dependencies:**
    Create a `requirements.txt` file with the following content:
    ```
    scapy
    dhcppython
    ntplib
    ```
    Then, install the packages using `pip3`:
    ```bash
    pip3 install -r requirements.txt
    ```
    *   `scapy` is the correct package for Python 3.
    *   `ntplib` is used for Python-based NTP checks. If it's not installed, NTP tests relying on it will be skipped.

## Usage

### Basic Usage

Run the main script with sudo privileges:

```bash
# Interactive mode (prompts for configuration)
sudo ./nrt.py

# Using a configuration file
sudo ./nrt.py --config nrt_config.json

# Enable debug output for more detailed information
sudo ./nrt.py --debug
```

### Configuration File

You can use a JSON configuration file instead of interactive prompts. Example configuration:

```json
{
  "mgmt_interface": "en0",
  "test_interface": "en7",
  "ip_address": "10.200.1.2",
  "netmask": "255.255.255.252",
  "gateway": "10.200.1.1",
  "nsb_subnet": "10.200.10.0/24",
  "sensor_subnet": "10.200.12.0/24",
  "client_subnet": "10.234.3.0/24",
  "run_dhcp_tests": true,
  "dhcp_servers": ["172.27.5.5"],
  "run_radius_tests": false,
  "radius_servers": [],
  "radius_secret": "",
  "radius_username": "",
  "radius_password": "",
  "run_custom_dns_tests": true,
  "custom_dns_servers": ["4.2.2.1", "1.1.1.1"],
  "run_custom_ntp_tests": false,
  "custom_ntp_servers": ["ntp.internal.example.com", "10.0.0.123"]
}
```

## How It Works

The Nile Readiness Test performs the following operations:

1. **Records the original state** of the network interface to restore it later
2. **Configures the test interface** with the specified IP address and netmask
3. **Creates loopback aliases** for each subnet (NSB, sensor, and client)
4. **Configures a static default route** via the specified gateway
5. **Detects OSPF Hello packets** on the test interface
6. **Runs connectivity tests**:
   - DNS resolution using specified DNS servers
   - DHCP relay tests (if enabled)
   - RADIUS authentication tests (if enabled)
   - NTP synchronization tests
   - HTTPS connectivity tests to Nile Cloud and AWS S3
   - SSL certificate validation
   - UDP connectivity tests
7. **Restores the original state** of the system
8. **Prints a summary** of test results

## Troubleshooting

- **Interface Configuration Fails**:
  - Verify you have permission to configure network interfaces (run as root/sudo)
  - Check if the interface exists and is not in use by another application
  - Ensure the IP address and netmask are valid and not already in use

- **Static Route Configuration Fails**:
  - Verify the gateway IP is reachable
  - Check if there are conflicting routes in the routing table
  - Ensure the interface is up and properly configured

- **DNS Tests Fail**:
  - Check if the DNS servers are reachable
  - Verify there is no firewall blocking DNS traffic (UDP/TCP port 53)
  - Try alternative DNS servers

- **DHCP Tests Fail**:
  - Verify the DHCP servers are reachable
  - Check if the client subnet is properly configured
  - Ensure there is no firewall blocking DHCP traffic (UDP ports 67/68)

- **RADIUS Tests Fail**:
  - Verify the RADIUS servers are reachable
  - Check if the shared secret, username, and password are correct
  - Ensure there is no firewall blocking RADIUS traffic (UDP port 1812)

- **NTP Tests Fail**:
  - Verify the NTP servers are reachable
  - Ensure there is no firewall blocking NTP traffic (UDP port 123)
  - Install the ntplib Python library if missing

- **HTTPS/SSL Tests Fail**:
  - Verify the target servers are reachable
  - Check if there is no firewall blocking HTTPS traffic (TCP port 443)
  - Ensure the system has proper root certificates installed

## License

This project is licensed under the MIT License.
