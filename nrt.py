#!/usr/bin/env python3
"""
nrt.py - Configures host interface, OSPF adjacency dynamically,
loopback interfaces, default route fallback, connectivity tests (DHCP/RADIUS,
NTP, HTTPS), then restores host to original state (including removing FRR config,
stopping FRR) and DNS changes.

This script runs in the default namespace and uses the specified interface for FRR tests,
allowing VNC to run in a separate namespace on another interface.

Usage: 
  sudo ./nrt.py [--debug] [--config CONFIG_FILE]
  
Options:
  --debug           Enable debug output
  --config FILE     Use JSON configuration file instead of interactive prompts
"""

import os
import sys
import shutil
import subprocess
import random
import ipaddress
import socket
import time
import json
import argparse
import re
from urllib.parse import urlparse
from scapy.config import conf
from scapy.all import sniff, sr1, send, Raw
from scapy.layers.inet import IP, UDP
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello

# Import dhcppython for improved DHCP testing
import dhcppython.client as dhcp_client
import dhcppython.options as dhcp_options
import dhcppython.utils as dhcp_utils

# Import ntplib for Python-based NTP checks
try:
    import ntplib
except ImportError:
    ntplib = None # Will be checked later

# Constants for Nile Connect tests
NILE_HOSTNAME = "ne-u1.nile-global.cloud"
S3_HOSTNAME = "s3.us-west-2.amazonaws.com"
GUEST_IPS = ["145.40.90.203","145.40.64.129","145.40.113.105","147.28.179.61"]
UDP_PORT = 6081
SSL_PORT = 443

# Check UDP connectivity using netcat
def check_udp_connectivity_netcat(ip: str, port: int = UDP_PORT, timeout: int = 5, source_ip: str = None) -> bool:
    """
    Check UDP connectivity using netcat (nc -vzu) with a timeout.
    
    Args:
        ip: IP address to check
        port: UDP port to check (default: 6081)
        timeout: Timeout in seconds (default: 5)
        source_ip: Optional source IP address to bind to for the test
        
    Returns:
        bool: True if connectivity successful, False otherwise
    """
    try:
        cmd = ['nc', '-vzu']
        if source_ip:
            cmd.extend(['-s', source_ip])
        cmd.extend([ip, str(port)])
        
        if DEBUG: print(f"  Running netcat command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        # Check for success indicators in output
        if "open" in result.stderr.lower():
            return True
            
        if result.returncode == 0:
            return True
            
        return False
    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        print(f"  Error: netcat (nc) command not found. Please install netcat.")
        return False
    except Exception as e:
        print(f"  Error: {e}")
        return False

# Check SSL certificate
def check_ssl_certificate(ip: str, hostname: str, expected_org: str) -> bool:
    """
    Test SSL certificate validity and organization.
    
    Args:
        ip: IP address to check
        hostname: Hostname for SNI
        expected_org: Expected organization in certificate issuer
        
    Returns:
        bool: True if SSL certificate is valid and contains expected organization, False otherwise
    """
    try:
        result = subprocess.run(
            ['openssl', 's_client', '-connect', f'{ip}:{SSL_PORT}', '-servername', hostname],
            capture_output=True,
            text=True
        )
        
        if "issuer=" in result.stdout:
            issuer_start = result.stdout.find("issuer=")
            issuer_end = result.stdout.find("\n", issuer_start)
            issuer = result.stdout[issuer_start:issuer_end].strip()
            
            # Check if issuer contains the expected organization
            if expected_org not in issuer:
                return False
                
            return True
        else:
            return False
    except Exception as e:
        print(f"  Error: {e}")
        return False



# Parse command line arguments
def parse_args():
    """
    Parse command line arguments for the Nile Readiness Test.
    
    Returns:
        argparse.Namespace: Parsed command line arguments
    """
    parser = argparse.ArgumentParser(description='Nile Readiness Test')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--config', type=str, help='Path to JSON configuration file')
    return parser.parse_args()

# Read configuration from JSON file
def read_config(config_file):
    """
    Read and parse the JSON configuration file.
    
    Args:
        config_file: Path to the JSON configuration file
        
    Returns:
        dict: Parsed configuration data
        
    Raises:
        SystemExit: If the file cannot be read or parsed
    """
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        print(f"Loaded configuration from {config_file}")
        return config
    except Exception as e:
        print(f"Error reading config file {config_file}: {e}")
        sys.exit(1)

# Parse arguments
args = parse_args()
DEBUG = args.debug

# ANSI color codes
GREEN = '\033[32m'
RED   = '\033[31m'
RESET = '\033[0m'

# Pre-flight checks
required_bins = {
    # 'vtysh': 'FRR (vtysh)', # Removed for macOS compatibility
    # 'radclient': 'FreeRADIUS client (radclient)', # Assuming it's available or handled by user
    'dig': 'DNS lookup utility (dig)',
    # 'sntp': 'SNTP utility (for NTP checks, replaces ntpdate)', # Replaced by ntplib
    'curl': 'HTTPS test utility (curl)', 
    'nc': 'Netcat (nc) for UDP connectivity testing',
    'openssl': 'OpenSSL for SSL certificate verification'
}
# Check for ntplib separately if it was not imported
if ntplib is None:
    print(f"{RED}Warning: 'ntplib' Python library not found. NTP tests will be skipped.{RESET}")
    print(f"{RED}Please install it: pip install ntplib{RESET}")
    # We could add 'sntp' back to required_bins here as a fallback if desired.

missing = [name for name in required_bins if shutil.which(name) is None]
if missing:
    print('Error: the following required tools are missing:')
    for name in missing:
        print(f'  - {required_bins[name]}')
    print()
    print('Please install them. On macOS, you might use Homebrew, e.g.:')
    print('  brew install dnsmasq (for dig) curl netcat openssl')
    if ntplib is None:
        print("  For NTP tests, also install 'ntplib' via pip: pip install ntplib")
    sys.exit(1)

# Wrapper for subprocess.run with debug
def run_cmd(cmd, **kwargs):
    """
    Execute a command with improved handling of output capture and debugging.
    
    This function wraps subprocess.run with additional features:
    - Debug output of commands being executed
    - Improved handling of stdout/stderr to avoid buffer deadlocks
    - Consistent error handling
    
    Args:
        cmd: Command to execute (list or string)
        **kwargs: Additional arguments to pass to subprocess.run
        
    Returns:
        subprocess.CompletedProcess: Result of the command execution
    """
    if DEBUG:
        printed = cmd if isinstance(cmd, str) else ' '.join(cmd)
        print(f'DEBUG: Running: {printed} | kwargs={kwargs}')
    
    # Use Popen instead of subprocess.run to avoid buffer deadlocks
    if kwargs.get('capture_output'):
        # Create pipes for stdout and stderr
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=kwargs.get('text', False),
            shell=kwargs.get('shell', False)
        )
        
        # Read stdout and stderr incrementally to avoid buffer deadlocks
        stdout_data = []
        stderr_data = []
        
        while True:
            # Read from stdout and stderr without blocking
            stdout_chunk = process.stdout.read(1024)
            stderr_chunk = process.stderr.read(1024)
            
            # If we got data, store it
            if stdout_chunk:
                stdout_data.append(stdout_chunk)
            if stderr_chunk:
                stderr_data.append(stderr_chunk)
            
            # Check if process has finished
            if process.poll() is not None:
                # Read any remaining data
                stdout_chunk = process.stdout.read()
                stderr_chunk = process.stderr.read()
                if stdout_chunk:
                    stdout_data.append(stdout_chunk)
                if stderr_chunk:
                    stderr_data.append(stderr_chunk)
                break
            
            # Small sleep to avoid CPU spinning
            time.sleep(0.01)
        
        # Join the data
        stdout_output = ''.join(stdout_data) if kwargs.get('text', False) else b''.join(stdout_data)
        stderr_output = ''.join(stderr_data) if kwargs.get('text', False) else b''.join(stderr_data)
        
        # Create a CompletedProcess object to match subprocess.run's return value
        proc = subprocess.CompletedProcess(
            args=cmd,
            returncode=process.returncode,
            stdout=stdout_output,
            stderr=stderr_output
        )
        
        if DEBUG:
            print('DEBUG: stdout:')
            print(proc.stdout)
            print('DEBUG: stderr:')
            print(proc.stderr)
    else:
        # If we're not capturing output, just use subprocess.run
        proc = subprocess.run(cmd, **kwargs)
    
    if kwargs.get('check') and proc.returncode != 0:
        if DEBUG:
            print(f'DEBUG: Command failed with return code {proc.returncode}')
        proc.check_returncode()
    
    return proc

# Prompt helper
def prompt_nonempty(prompt):
    """
    Prompt the user for input and ensure a non-empty response.
    
    Args:
        prompt: The prompt text to display to the user
        
    Returns:
        str: The user's non-empty input
    """
    while True:
        val = input(prompt).strip()
        if val:
            return val
        print('  -> This value cannot be blank.')

# Gather user input
def get_user_input(config_file=None):
    """
    Gather network configuration input from either a config file or interactive prompts.
    
    This function handles both configuration file parsing and interactive user input
    for setting up network interfaces, subnets, and test parameters.
    
    Args:
        config_file: Optional path to a JSON configuration file
        
    Returns:
        tuple: A tuple containing all configuration parameters:
            (test_iface, ip_addr, netmask, gateway, mgmt_interface,
            mgmt1, mgmt2, client_subnet,
            dhcp_servers, radius_servers, secret, username, password,
            run_dhcp, run_radius, custom_dns_servers, custom_ntp_servers)
    """
    # If config file is provided, use it
    if config_file:
        config = read_config(config_file)
        test_iface = config.get('test_interface', 'enxf0a731f41761')
        ip_addr = config.get('ip_address')
        netmask = config.get('netmask')
        gateway = config.get('gateway')
        mgmt_interface = config.get('mgmt_interface', 'end0')
        mgmt1 = config.get('nsb_subnet')
        mgmt2 = config.get('sensor_subnet')
        client_subnet = config.get('client_subnet')
        run_dhcp = config.get('run_dhcp_tests', False)
        dhcp_servers = config.get('dhcp_servers', [])
        run_radius = config.get('run_radius_tests', False)
        radius_servers = config.get('radius_servers', [])
        secret = config.get('radius_secret')
        username = config.get('radius_username')
        password = config.get('radius_password')
        run_custom_dns_tests = config.get('run_custom_dns_tests', False)
        custom_dns_servers = config.get('custom_dns_servers', []) if run_custom_dns_tests else []
        run_custom_ntp_tests = config.get('run_custom_ntp_tests', False)
        custom_ntp_servers = config.get('custom_ntp_servers', []) if run_custom_ntp_tests else []
        
        # Validate required fields
        missing = []
        for field, value in [
            ('ip_address', ip_addr),
            ('netmask', netmask),
            ('gateway', gateway),
            ('nsb_subnet', mgmt1),
            ('sensor_subnet', mgmt2),
            ('client_subnet', client_subnet)
        ]:
            if not value:
                missing.append(field)
        
        if missing:
            print(f"Error: Missing required fields in config file: {', '.join(missing)}")
            sys.exit(1)
            
        # Validate RADIUS fields if RADIUS tests are enabled
        if run_radius:
            missing = []
            for field, value in [
                ('radius_servers', radius_servers),
                ('radius_secret', secret),
                ('radius_username', username),
                ('radius_password', password)
            ]:
                if not value:
                    missing.append(field)
            
            if missing:
                print(f"Error: RADIUS tests enabled but missing fields: {', '.join(missing)}")
                sys.exit(1)
        
        # Validate DHCP fields if DHCP tests are enabled
        if run_dhcp and not dhcp_servers:
            print("Error: DHCP tests enabled but no DHCP servers specified")
            sys.exit(1)
            
        print("\nUsing configuration from file:")
        print(f"  Management Interface: {mgmt_interface}")
        print(f"  NSB Testing Interface: {test_iface}")
        print(f"  IP Address: {ip_addr}")
        print(f"  Netmask: {netmask}")
        print(f"  Gateway: {gateway}")
        print(f"  NSB Subnet: {mgmt1}")
        print(f"  Sensor Subnet: {mgmt2}")
        print(f"  Client Subnet: {client_subnet}")
        print(f"  Run DHCP Tests: {run_dhcp}")
        if run_dhcp:
            print(f"  DHCP Servers: {', '.join(dhcp_servers)}")
        print(f"  Run RADIUS Tests: {run_radius}")
        if run_radius:
            print(f"  RADIUS Servers: {', '.join(radius_servers)}")
        print(f"  Run Custom DNS Tests: {run_custom_dns_tests}")
        if run_custom_dns_tests:
            print(f"  Custom DNS Servers: {', '.join(custom_dns_servers)}")
        print(f"  Run Custom NTP Tests: {run_custom_ntp_tests}")
        if run_custom_ntp_tests:
            print(f"  Custom NTP Servers: {', '.join(custom_ntp_servers)}")
    else:
        # Interactive mode
        print("\nNetwork Interface Configuration:")
        print("--------------------------------")
        mgmt_interface = prompt_nonempty('Management interface of host to keep enabled (default: end0): ') or 'end0'
        test_iface     = prompt_nonempty('Interface for Nile Readiness tests (default: enxf0a731f41761): ') or 'enxf0a731f41761'
        ip_addr       = prompt_nonempty('IP address for NSB Gateway interface: ')
        netmask       = prompt_nonempty('Netmask (e.g. 255.255.255.0): ')
        gateway       = prompt_nonempty('Router or Firewall IP: ')
        mgmt1         = prompt_nonempty('NSB subnet (CIDR, e.g. 192.168.1.0/24): ')
        mgmt2         = prompt_nonempty('Sensor subnet (CIDR): ')
        client_subnet = prompt_nonempty('Client subnet (CIDR): ')

        run_dhcp = input('Perform DHCP tests? [y/N]: ').strip().lower().startswith('y')
        dhcp_servers = []
        if run_dhcp:
            dhcp_servers = [ip.strip() for ip in prompt_nonempty(
                'DHCP server IP(s) (comma-separated): ').split(',')]

        run_radius = input('Perform RADIUS tests? [y/N]: ').strip().lower().startswith('y')
        radius_servers = []
        secret = username = password = None
        if run_radius:
            radius_servers = [ip.strip() for ip in prompt_nonempty(
                'RADIUS server IP(s) (comma-separated): ').split(',')]
            secret   = prompt_nonempty('RADIUS shared secret: ')
            username = prompt_nonempty('RADIUS test username: ')
            password = prompt_nonempty('RADIUS test password: ')

    # For interactive mode, custom_dns_servers and custom_ntp_servers are empty lists
    if not config_file:
        custom_dns_servers = []
        custom_ntp_servers = []
        
        # Ask for custom DNS servers
        custom_dns = input('Add custom DNS servers for testing? [y/N]: ').strip().lower()
        if custom_dns.startswith('y'):
            custom_dns_input = prompt_nonempty('Enter custom DNS server IP(s) (comma-separated): ')
            custom_dns_servers = [ip.strip() for ip in custom_dns_input.split(',')]
            
        # Ask for custom NTP servers
        custom_ntp = input('Add custom NTP servers for testing? [y/N]: ').strip().lower()
        if custom_ntp.startswith('y'):
            custom_ntp_input = prompt_nonempty('Enter custom NTP server(s) (comma-separated): ')
            custom_ntp_servers = [server.strip() for server in custom_ntp_input.split(',')]
    
    # Print custom DNS and NTP servers if provided
    if custom_dns_servers:
        print(f"  Custom DNS Servers: {', '.join(custom_dns_servers)}")
    if custom_ntp_servers:
        print(f"  Custom NTP Servers: {', '.join(custom_ntp_servers)}")
    
    return (test_iface, ip_addr, netmask, gateway, mgmt_interface,
            mgmt1, mgmt2, client_subnet,
            dhcp_servers, radius_servers, secret, username, password,
            run_dhcp, run_radius, custom_dns_servers, custom_ntp_servers)

# Record/restore host state
def record_state(iface):
    """
    Record the current state of a network interface and system configuration.
    
    This function captures the current state of the specified interface,
    including IP addresses, routes, FRR configuration, and DNS settings,
    so they can be restored later.
    
    Args:
        iface: The network interface to record state for
        
    Returns:
        dict: A dictionary containing the recorded state information
    """
    if DEBUG:
        print(f"Recording state of interface {iface}...")
    state = {}
    if DEBUG:
        print(f"Recording state of interface {iface} for macOS...")
    
    # Get current IP addresses for the interface
    state['addrs'] = []
    try:
        # Ensure interface is up to read its config, then restore original state if it was down
        original_ifconfig_output_for_state = run_cmd(['ifconfig', iface], capture_output=True, text=True).stdout
        is_originally_up = '<UP,' in original_ifconfig_output_for_state.split(f"{iface}:")[1].split('\n')[0] if f"{iface}:" in original_ifconfig_output_for_state else False
        
        if not is_originally_up:
            if DEBUG: print(f"Temporarily bringing up {iface} to record its state.")
            run_cmd(['ifconfig', iface, 'up'], check=False)
            time.sleep(0.5) # Give it a moment

        ifconfig_output = run_cmd(['ifconfig', iface], capture_output=True, text=True, check=True).stdout
        for line in ifconfig_output.splitlines():
            line_stripped = line.strip()
            if line_stripped.startswith('inet '): # IPv4
                parts = line_stripped.split()
                ip_addr_val = parts[1]
                try:
                    netmask_val_hex = parts[parts.index('netmask') + 1]
                    netmask_val = socket.inet_ntoa(int(netmask_val_hex, 16).to_bytes(4, 'big'))
                    prefix = ipaddress.IPv4Network(f'0.0.0.0/{netmask_val}').prefixlen
                    state['addrs'].append(f"{ip_addr_val}/{prefix}")
                except (ValueError, IndexError):
                    if DEBUG: print(f"Could not parse netmask for IP {ip_addr_val} on {iface}. Line: '{line_stripped}'")
            # elif line_stripped.startswith('inet6 '): # IPv6 - currently not fully handled by script restore
            #     pass 
        
        if not is_originally_up: # Restore original down state if we brought it up
             if DEBUG: print(f"Restoring {iface} to its original down state.")
             run_cmd(['ifconfig', iface, 'down'], check=False)

    except subprocess.CalledProcessError as e:
        if DEBUG:
            print(f"DEBUG: Error getting addresses for {iface} in record_state: {e}. It might be down or not exist.")
    except Exception as e:
        if DEBUG:
            print(f"DEBUG: General error in record_state for addresses: {e}")


    # Get current default routes
    state['routes'] = []
    try:
        route_output = run_cmd(['netstat', '-nr', '-f', 'inet'], capture_output=True, text=True, check=True).stdout
        for line in route_output.splitlines():
            if line.startswith('default') or line.startswith('0.0.0.0/0'): # Common for default route
                state['routes'].append(line.strip())
    except subprocess.CalledProcessError as e:
        if DEBUG:
            print(f"DEBUG: Error getting default routes in record_state: {e}")
    except Exception as e:
        if DEBUG:
            print(f"DEBUG: General error in record_state for routes: {e}")

    # FRR specific, remove for macOS
    # with open('/etc/frr/daemons') as f: state['daemons'] = f.read()
    # state['daemons'] = "" # Placeholder or remove if not used elsewhere in restore
    with open('/etc/resolv.conf') as f: state['resolv'] = f.read() # This file exists on macOS
    # FRR and systemd specific, remove for macOS
    # svc = run_cmd(['systemctl','is-enabled','frr'], capture_output=True, text=True)
    # state['frr_enabled'] = (svc.returncode == 0)
    # state['frr_enabled'] = False # Placeholder
    return state

def restore_state(iface, state):
    """
    Restore the network interface and system configuration to its original state.
    
    This function reverses the changes made during testing by:
    - Removing dummy interfaces
    - Restoring original IP addresses
    - Restoring original routes
    - Restoring FRR configuration
    - Restoring DNS settings
    - Stopping and disabling FRR service
    
    Args:
        iface: The network interface to restore
        state: The state dictionary created by record_state()
    """
    if DEBUG:
        print('\nRestoring original state...')
    
    # First, remove dummy interfaces (aliases on lo0 for macOS)
    if DEBUG:
        print("Removing loopback aliases added for testing (macOS)...")
    # Retrieve subnets from a global or passed state if necessary, or re-calculate.
    # For now, assuming we can re-calculate or have them available.
    # This part needs access to m1, m2, client_subnet values used in add_loopbacks.
    # We'll need to adjust how these are passed or stored.
    # As a placeholder, let's assume a function `get_loopback_ips_to_remove()` exists
    # or that we modify `record_state` to store them if `add_loopbacks` was called.
    # For now, this is a conceptual cleanup.
    # A simple way is to try removing the expected IPs if they were configured.
    # This is a simplification; a more robust method would store the exact IPs added.
    if 'loopback_ips_added' in state: # Assuming add_loopbacks stores this
        for loop_ip in state['loopback_ips_added']:
            if DEBUG: print(f"  Removing loopback alias {loop_ip} from lo0")
            run_cmd(['ifconfig', 'lo0', 'inet', loop_ip, '-alias'], check=False, capture_output=True)
            run_cmd(['ifconfig', 'lo0', 'inet', loop_ip, 'delete'], check=False, capture_output=True) # Alternative
    else:
        if DEBUG: print("  No specific loopback IPs recorded in state to remove.")


    # Flush the interface (remove all current IPs from the test interface)
    if DEBUG:
        print(f"Flushing interface {iface} by removing its current IPs (macOS)...")
    try:
        current_ifconfig = run_cmd(['ifconfig', iface], capture_output=True, text=True).stdout
        ips_to_remove = []
        for line in current_ifconfig.splitlines():
            line_stripped = line.strip()
            if line_stripped.startswith('inet '):
                parts = line_stripped.split()
                ips_to_remove.append(parts[1])
        
        for ip_to_remove in ips_to_remove:
            if DEBUG: print(f"  Removing IP {ip_to_remove} from {iface}")
            # On macOS, 'delete' is often used for the primary IP, 'remove' or '-alias' for aliases.
            # Try 'delete' first. If it fails, it might be an alias or already gone.
            run_cmd(['ifconfig', iface, 'inet', ip_to_remove, 'delete'], check=False, capture_output=True)
            run_cmd(['ifconfig', iface, 'inet', ip_to_remove, '-alias'], check=False, capture_output=True) # For aliases
            run_cmd(['ifconfig', iface, 'inet', ip_to_remove, 'remove'], check=False, capture_output=True) # Alternative

    except subprocess.CalledProcessError:
        if DEBUG: print(f"  Interface {iface} might already be clean or down during flush.")
    except Exception as e:
        if DEBUG: print(f"  Error flushing {iface}: {e}")

    # Add back the original addresses
    if DEBUG:
        print("Restoring original IP addresses (macOS)...")
    for addr_cidr in state.get('addrs', []):
        try:
            ip_interface = ipaddress.IPv4Interface(addr_cidr)
            ip_val = str(ip_interface.ip)
            netmask_val = str(ip_interface.netmask)
            if DEBUG: print(f"  Adding {ip_val} netmask {netmask_val} to {iface}")
            # For the first IP, it might be set without 'add'. For subsequent, 'alias' or 'add' is needed.
            # This logic might need refinement based on whether it's the primary or an alias.
            # A common way is to set the first IP, then alias others.
            # If state['addrs'] contains multiple, the first one is primary, others are aliases.
            is_primary_ip = state['addrs'].index(addr_cidr) == 0
            if is_primary_ip:
                 run_cmd(['ifconfig', iface, 'inet', ip_val, 'netmask', netmask_val], check=False, capture_output=True)
            else: # It's an alias
                 run_cmd(['ifconfig', iface, 'inet', ip_val, 'netmask', netmask_val, 'alias'], check=False, capture_output=True)
        except ValueError as e:
            if DEBUG: print(f"  Skipping invalid address {addr_cidr} for restore: {e}")
        except subprocess.CalledProcessError as e:
            if DEBUG: print(f"  Failed to add {addr_cidr} to {iface} during restore: {e.stderr}")
        except Exception as e:
            if DEBUG: print(f"  General error restoring address {addr_cidr}: {e}")

    # Make sure the interface is up
    if DEBUG:
        print(f"Ensuring interface {iface} is up (macOS)...")
    run_cmd(['ifconfig', iface, 'up'], check=False, capture_output=True)

    # Restore default routes
    if DEBUG: print("Attempting to remove current default routes (macOS)...")
    # Loop to remove any default routes that might have been added by the script or system
    # This is a best-effort removal.
    for _ in range(3): # Try a few times as 'route delete default' removes one at a time
        run_cmd(['route', '-n', 'delete', 'default'], check=False, capture_output=True) # -n to avoid DNS lookups

    if DEBUG:
        print("Restoring original default routes (macOS)...")
    for route_line in state.get('routes', []):
        parts = route_line.split()
        if len(parts) >= 2 and (parts[0] == 'default' or parts[0] == '0.0.0.0/0'):
            gateway_ip = parts[1]
            cmd = ['route', '-n', 'add', 'default', gateway_ip] # -n to avoid DNS lookups
            # Interface specification for default route on macOS is usually implicit or handled by gateway reachability
            if DEBUG: print(f"  Adding default route: {' '.join(cmd)}")
            run_cmd(cmd, check=False, capture_output=True)
    
    # Restore FRR configuration - Removed for macOS
    # if DEBUG:
    #     print("Restoring FRR configuration...")
    # if state.get('daemons'): # Check if daemons key exists
    #     with open('/etc/frr/daemons','w') as f: f.write(state['daemons'])
    # run_cmd(['rm','-f','/etc/frr/frr.conf'], check=False, capture_output=True) # FRR specific
    
    # Restore DNS configuration
    if DEBUG:
        print("Restoring DNS configuration...")
    with open('/etc/resolv.conf','w') as f: f.write(state['resolv']) # This file exists on macOS
    
    # Stop and disable FRR - Removed for macOS
    # if DEBUG:
    #     print("Stopping and disabling FRR...")
    # run_cmd(['systemctl','stop','frr'], check=False, capture_output=True) # systemd specific
    # run_cmd(['systemctl','disable','frr'], check=False, capture_output=True) # systemd specific
    
    if DEBUG:
        # print('Removed FRR config, stopped service, restored DNS.')
        print('Restored DNS. FRR parts skipped for macOS.')

# Test TLS connectivity using openssl s_client
def test_tls_connectivity_openssl(hostname: str, port: int = SSL_PORT, source_ip: str = None, timeout_duration: int = 10) -> bool:
    """
    Test basic TLS connectivity to a host and port using openssl s_client.
    Checks if a TLS handshake can be initiated. Does not validate the certificate itself here.

    Args:
        hostname: The hostname to connect to.
        port: The port to connect to (default: SSL_PORT).
        source_ip: Optional source IP to bind to.
        timeout_duration: Timeout for the openssl command.

    Returns:
        bool: True if TLS handshake initiated successfully, False otherwise.
    """
    if DEBUG:
        print(f"  Testing TLS connectivity to {hostname}:{port}" + (f" from {source_ip}" if source_ip else ""))

    # Resolve hostname to IP first using our helper function
    resolved_ip = resolve_hostname_to_ip(hostname)
    if resolved_ip != hostname:
        if DEBUG: print(f"  Using resolved IP {resolved_ip} for hostname {hostname}")
        # Use the resolved IP for the connection but keep the original hostname for SNI
        connect_target = f"{resolved_ip}:{port}"
    else:
        if DEBUG: print(f"  Using original hostname {hostname} for connection")
        connect_target = f"{hostname}:{port}"
    
    cmd = ['openssl', 's_client', '-connect', connect_target, '-servername', hostname]
    if source_ip:
        # openssl s_client -bind needs host:port, port 0 means OS chooses source port
        cmd.extend(['-bind', f'{source_ip}:0']) 

    # Use 'echo "Q"' to send a quit command to s_client after connection to close it cleanly.
    # This is piped to stdin of the openssl command.
    openssl_proc = None
    try:
        if DEBUG: print(f"    Running command: echo \"Q\" | {' '.join(cmd)}")
        # Using Popen to handle stdin piping
        echo_proc = subprocess.Popen(['echo', 'Q'], stdout=subprocess.PIPE)
        openssl_proc = subprocess.Popen(
            cmd,
            stdin=echo_proc.stdout,
            stdout=subprocess.PIPE, # Capture to avoid printing to console unless debug
            stderr=subprocess.PIPE, # Capture to avoid printing to console unless debug
            text=True
        )
        # Allow echo_proc to send its output
        if echo_proc.stdout:
            echo_proc.stdout.close() 
        
        # Wait for openssl_proc to complete with a timeout
        try:
            stdout, stderr = openssl_proc.communicate(timeout=timeout_duration)
            returncode = openssl_proc.returncode
            if DEBUG:
                print(f"    openssl s_client stdout:\n{stdout}")
                print(f"    openssl s_client stderr:\n{stderr}")
                print(f"    openssl s_client returncode: {returncode}")
            # A return code of 0 usually indicates a successful handshake.
            # s_client might also print "Verify return code: 0 (ok)" on success even if cert is self-signed.
            # For basic connectivity, return code 0 is the primary indicator.
            return returncode == 0
        except subprocess.TimeoutExpired:
            if openssl_proc:
                openssl_proc.kill()
                openssl_proc.communicate() # Clean up
            if DEBUG: print(f"    openssl s_client command timed out after {timeout_duration}s.")
            return False

    except FileNotFoundError:
        print(f"  Error: openssl command not found.")
        return False
    except Exception as e:
        print(f"  Error during openssl s_client test to {hostname}:{port}: {e}")
        return False
    finally:
        # Ensure echo_proc is cleaned up if it was created
        if 'echo_proc' in locals() and hasattr(echo_proc, 'poll') and echo_proc.poll() is None: # Ensure echo_proc exists and has poll
            echo_proc.kill()
            echo_proc.communicate()

# Helper function to resolve hostname to IP using dig
def resolve_hostname_to_ip(hostname):
    """
    Resolve a hostname to an IP address using dig.
    
    Args:
        hostname: The hostname to resolve.
        
    Returns:
        str: The resolved IP address, or the original hostname if resolution fails or if the hostname is already an IP.
    """
    # Check if the hostname is already an IP address
    try:
        ipaddress.ip_address(hostname)
        if DEBUG: print(f"  {hostname} is already an IP address, no resolution needed")
        return hostname
    except ValueError:
        pass  # Not an IP address, continue with resolution
    
    if DEBUG: print(f"  Attempting to resolve {hostname} using dig...")
    try:
        # Use dig to resolve the hostname
        r = run_cmd(['dig', hostname, '+short'], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            # Take the first IP address returned
            resolved_ip = r.stdout.strip().split('\n')[0]
            if DEBUG: print(f"  Resolved {hostname} to {resolved_ip}")
            return resolved_ip
        else:
            if DEBUG: print(f"  Failed to resolve {hostname} using dig")
            return hostname  # Return the original hostname if resolution fails
    except Exception as e:
        if DEBUG: print(f"  Error resolving {hostname}: {e}")
        return hostname  # Return the original hostname if an error occurs

# NTP check using ntplib
def test_ntp_with_ntplib(ntp_server_host, timeout=5, source_ip=None):
    """
    Test NTP connectivity using the ntplib library.

    Args:
        ntp_server_host: The hostname or IP of the NTP server.
        timeout: Timeout in seconds for the request.
        source_ip: Optional source IP to bind to. Note: This requires custom socket handling.

    Returns:
        bool: True if NTP query was successful, False otherwise.
    """
    if ntplib is None:
        if DEBUG: print(f"  ntplib not available, skipping NTP test for {ntp_server_host}")
        return False
    
    # First try to resolve the hostname to an IP address
    server_ip = resolve_hostname_to_ip(ntp_server_host)
    if server_ip != ntp_server_host:
        if DEBUG: print(f"  Using resolved IP {server_ip} for NTP server {ntp_server_host}")
    else:
        if DEBUG: print(f"  Using original hostname/IP {ntp_server_host} for NTP test")
    
    if source_ip:
        if DEBUG: print(f"  Attempting NTP query to {server_ip} with source IP {source_ip}")
        # Custom socket handling for source IP binding
        try:
            # Create a custom socket with the source IP bound
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            try:
                # Bind to the source IP
                sock.bind((source_ip, 0))  # Let OS choose source port
                
                # Create NTPClient with our custom socket
                client = ntplib.NTPClient()
                
                if DEBUG: print(f"  Socket bound to {source_ip}, querying NTP server {ntp_server_host}")
                
                # Use the socket for the NTP request
                try:
                    # We need to manually handle the NTP request since we're using a custom socket
                    # This is a simplified version - in production you'd want more robust handling
                    sock.settimeout(timeout)
                    
                    # Send a basic NTP request packet (mode 3 - client)
                    # This is a very basic implementation - ntplib's internal implementation is more robust
                    ntp_packet = bytearray(48)  # Standard NTP packet size
                    ntp_packet[0] = 0x1B  # LI=0, Version=3, Mode=3 (client)
                    
                    # Use the already resolved IP address
                    try:
                        # If server_ip is still a hostname (resolution failed), try to resolve it with socket
                        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', server_ip):
                            if DEBUG: print(f"  Resolving {server_ip} using socket.gethostbyname")
                            server_ip = socket.gethostbyname(server_ip)
                    except socket.gaierror as e:
                        if DEBUG: print(f"  DNS resolution failed for NTP server {server_ip}: {e}")
                        return False
                    
                    # Send the packet
                    sock.sendto(ntp_packet, (server_ip, 123))
                    
                    # Wait for a response
                    try:
                        data, addr = sock.recvfrom(1024)
                        if data:
                            if DEBUG: print(f"  Received NTP response from {addr[0]}")
                            return True
                        return False
                    except socket.timeout:
                        if DEBUG: print(f"  NTP query to {ntp_server_host} timed out after {timeout}s")
                        return False
                    
                except Exception as e:
                    if DEBUG: print(f"  Error during NTP request to {ntp_server_host} with source IP {source_ip}: {e}")
                    return False
                    
            except socket.error as e:
                if DEBUG: print(f"  Failed to bind to source IP {source_ip}: {e}")
                if DEBUG: print(f"  Falling back to default source IP selection")
                # Fall back to standard NTP request without source IP binding
                return test_ntp_with_ntplib(server_ip, timeout, None)
                
        except Exception as e:
            if DEBUG: print(f"  Error creating socket for NTP test with source IP {source_ip}: {e}")
            if DEBUG: print(f"  Falling back to default source IP selection")
            # Fall back to standard NTP request without source IP binding
            return test_ntp_with_ntplib(server_ip, timeout, None)
        finally:
            # Ensure socket is closed
            if 'sock' in locals() and sock:
                sock.close()
    else:
        # Standard NTP request without source IP binding
        client = ntplib.NTPClient()
        if DEBUG: print(f"  Querying NTP server {server_ip} with ntplib (timeout={timeout}s)")
        try:
            response = client.request(server_ip, version=3, port=123, timeout=timeout)
            if DEBUG: print(f"  NTP response from {server_ip}: Offset {response.offset:.4f}s")
            return True # Success if request doesn't raise an exception
        except ntplib.NTPException as e:
            if DEBUG: print(f"  NTP query to {server_ip} failed (ntplib NTPException): {e}")
            return False
        except socket.gaierror as e:
            if DEBUG: print(f"  DNS resolution failed for NTP server {server_ip}: {e}")
            return False
        except socket.timeout:
            if DEBUG: print(f"  NTP query to {server_ip} timed out after {timeout}s (ntplib).")
            return False
        except Exception as e: # Catch any other unexpected ntplib or socket errors
            if DEBUG: print(f"  Unexpected error during NTP query to {server_ip} (ntplib): {e}")
            return False

# Detect OSPF Hello packets using Scapy
def detect_ospf_hello(iface, timeout=15):
    """
    Sniff for OSPF Hello packets on the specified interface for a short duration.
    Reports if any are detected but does not validate neighbor state.

    Args:
        iface: The network interface to sniff on
        timeout: Time to sniff in seconds (default: 15)

    Returns:
        bool: True if an OSPF Hello packet was detected, False otherwise.
    """
    print(f'\n=== OSPF Hello Detection on {iface} (Timeout: {timeout}s) ===')
    try:
        # Sniff for the first OSPF packet (IP protocol 89)
        pkts = sniff(iface=iface, filter='ip proto 89', timeout=timeout, count=1, store=True)
        if not pkts:
            print(f'No OSPF packets detected on {iface} within {timeout} seconds.')
            return False
        
        pkt = pkts[0]
        # Check if it's specifically an OSPF Hello (Type 1)
        if OSPF_Hdr in pkt and pkt[OSPF_Hdr].type == 1 and OSPF_Hello in pkt:
            src = pkt[IP].src
            area = pkt[OSPF_Hdr].area
            # Ensure area is string, might be int or dotted decimal
            area_str = str(area) 
            # Handle potential integer area format from Scapy parsing
            if isinstance(area, int):
                 area_str = str(ipaddress.IPv4Address(area))

            hi = pkt[OSPF_Hello].hellointerval
            di = pkt[OSPF_Hello].deadinterval
            print(f"{GREEN}Detected OSPF Hello from {src}{RESET} (Area: {area_str}, HelloInt: {hi}s, DeadInt: {di}s)")
            return True
        elif OSPF_Hdr in pkt:
             print(f"{GREEN}Detected non-Hello OSPF packet (Type: {pkt[OSPF_Hdr].type}) from {pkt[IP].src}{RESET}")
             return True # Still detected OSPF activity
        else:
             print(f"Detected IP protocol 89 packet from {pkt[IP].src}, but not parsed as OSPF Hello.")
             return False # Technically not the target, but indicates potential issue or non-standard packet

    except ImportError:
         print(f"{RED}Error: Scapy or OSPF layer not properly installed/found.{RESET}")
         return False
    except OSError as e:
         print(f"{RED}Error sniffing on interface {iface}: {e}. Check permissions and interface name.{RESET}")
         return False
    except Exception as e:
         print(f"{RED}An unexpected error occurred during OSPF sniffing: {e}{RESET}")
         return False

# Configure main interface
def configure_interface(iface, ip_addr, netmask, mgmt_interface='end0'):
    """
    Configure the main network interface for testing.
    
    This function:
    - Disables all interfaces except loopback and management interface
    - Configures the specified interface with the given IP address and netmask
    - Ensures the interface is up and properly configured
    
    Args:
        iface: The network interface to configure
        ip_addr: The IP address to assign to the interface
        netmask: The netmask in dotted decimal notation (e.g., 255.255.255.0)
        mgmt_interface: The management interface to keep enabled (default: end0)
        
    Returns:
        bool: True if the interface was successfully configured, False otherwise
    """

    if DEBUG:
        print(f'Configuring {iface} → {ip_addr}/{netmask}')
    
    # Get a list of all network interfaces
    if DEBUG:
        print("Getting list of network interfaces for macOS...")
    try:
        interfaces_output = run_cmd(['ifconfig', '-l'], capture_output=True, text=True, check=True).stdout
        interfaces = interfaces_output.strip().split()
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error getting interface list: {e}{RESET}")
        return False # Cannot proceed without interface list

    # macOS: Dummy interfaces are typically aliases on lo0. Cleanup is handled by restore_state.
    if DEBUG:
        print("Skipping dummy interface cleanup in configure_interface (macOS).")

    # Check if management interface has a default gateway and remove it
    if mgmt_interface in interfaces and mgmt_interface != iface:
        if DEBUG:
            print(f"Checking if management interface {mgmt_interface} has a default gateway (macOS)...")
        try:
            route_output = run_cmd(['netstat', '-nr', '-f', 'inet'], capture_output=True, text=True).stdout
            mgmt_default_route_found = False
            for line in route_output.splitlines():
                if line.startswith('default') and mgmt_interface in line:
                    gateway_ip_on_mgmt = line.split()[1]
                    if DEBUG:
                        print(f"Attempting to remove default gateway {gateway_ip_on_mgmt} via {mgmt_interface}...")
                    run_cmd(['route', '-n', 'delete', 'default', gateway_ip_on_mgmt, '-ifp', mgmt_interface], check=False, capture_output=True)
                    # Try a more general delete if the specific one fails or isn't precise enough
                    run_cmd(['route', '-n', 'delete', 'default', '-ifp', mgmt_interface], check=False, capture_output=True)
                    if DEBUG: print(f"Default gateway potentially removed from {mgmt_interface}.")
                    mgmt_default_route_found = True
                    break 
            if not mgmt_default_route_found and DEBUG:
                print(f"No default route found specifically for {mgmt_interface}.")
        except subprocess.CalledProcessError as e:
            if DEBUG: print(f"Error checking/removing default route from {mgmt_interface}: {e}")


    # Disable all interfaces except loopback (lo0) and management interface
    if DEBUG:
        print(f"Disabling all interfaces except lo0 and {mgmt_interface} (management interface) (macOS)...")
    # Filter out common non-configurable or virtual interfaces on macOS
    interfaces_to_consider_disabling = [i for i in interfaces if i != 'lo0' and i != mgmt_interface and 
                                        not i.startswith(('gif', 'stf', 'awdl', 'llw', 'utun', 'bridge', 'ppp'))]
    
    for interface_to_down in interfaces_to_consider_disabling:
        if interface_to_down == iface: # Don't disable the test interface itself yet
            continue
        if DEBUG:
            print(f"Disabling interface {interface_to_down}...")
        run_cmd(['ifconfig', interface_to_down, 'down'], check=False, capture_output=True)
    
    # Configure the specified interface
    if DEBUG:
        print(f'Configuring {iface} with IP {ip_addr} and netmask {netmask} (macOS)...')
    
    # Flush existing IPs from the target interface first
    try:
        current_ifconfig = run_cmd(['ifconfig', iface], capture_output=True, text=True).stdout
        ips_to_remove = []
        for line in current_ifconfig.splitlines():
            line_stripped = line.strip()
            if line_stripped.startswith('inet '):
                parts = line_stripped.split()
                ips_to_remove.append(parts[1])
        for ip_to_remove in ips_to_remove:
            if ip_to_remove == ip_addr: continue # Don't remove the IP we are about to set if it's already there
            if DEBUG: print(f"  Removing existing IP {ip_to_remove} from {iface}")
            run_cmd(['ifconfig', iface, 'inet', ip_to_remove, 'delete'], check=False, capture_output=True)
            run_cmd(['ifconfig', iface, 'inet', ip_to_remove, '-alias'], check=False, capture_output=True)
    except subprocess.CalledProcessError:
        if DEBUG: print(f"  Interface {iface} might have no IPs to flush or is down before configuration.")
    except Exception as e:
        if DEBUG: print(f"  Error flushing {iface} before config: {e}")

    # Set the new IP address and netmask
    try:
        run_cmd(['ifconfig', iface, 'inet', ip_addr, 'netmask', netmask], check=True)
    except subprocess.CalledProcessError as e:
        print(f"{RED}ERROR: Failed to set IP {ip_addr} on {iface}: {e.stderr}{RESET}")
        return False # Critical failure

    # Enable the interface
    if DEBUG:
        print(f"Enabling {iface} (macOS)...")
    try:
        run_cmd(['ifconfig', iface, 'up'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"{RED}ERROR: Failed to bring up {iface}: {e.stderr}{RESET}")
        return False # Critical failure
    
    # Ensure the interface is up and properly configured with retry logic
    if DEBUG:
        print(f"\nEnsuring interface {iface} is up and properly configured (macOS)...")
    max_retries = 5
    retry_delay = 2
    interface_up_and_configured = False
    
    for attempt in range(max_retries):
        try:
            ifconfig_output = run_cmd(['ifconfig', iface], capture_output=True, text=True, check=True).stdout
            # Check for <UP,...> in flags and correct inet & netmask
            if_flags_line = ""
            if_details_lines = ""
            if f"{iface}:" in ifconfig_output:
                if_block = ifconfig_output.split(f"{iface}:")[1]
                if_flags_line = if_block.split('\n')[0]
                if_details_lines = "\n".join(if_block.split('\n')[1:])

            is_up_flag = "<UP," in if_flags_line
            # Netmask on macOS ifconfig output is often in hex, e.g., netmask 0xffffff00
            hex_netmask = '0x' + socket.inet_aton(netmask).hex()
            ip_is_set = f'inet {ip_addr} ' in if_details_lines
            netmask_is_set = hex_netmask in if_details_lines

            if is_up_flag and ip_is_set and netmask_is_set:
                if DEBUG:
                    print(f"Interface {iface} is up and properly configured with IP {ip_addr}, Netmask {netmask} (Hex: {hex_netmask})")
                interface_up_and_configured = True
                break
            else:
                if DEBUG:
                    print(f"Attempt {attempt+1}/{max_retries}: Interface {iface} not fully configured.")
                    if not is_up_flag: print(f"  - Interface flags do not show UP: {if_flags_line}")
                    if not ip_is_set: print(f"  - IP {ip_addr} not found in ifconfig output.")
                    if not netmask_is_set: print(f"  - Netmask {netmask} (Hex: {hex_netmask}) not found in ifconfig output.")
                # Try re-applying config
                run_cmd(['ifconfig', iface, 'inet', ip_addr, 'netmask', netmask], check=False)
                run_cmd(['ifconfig', iface, 'up'], check=False)
                time.sleep(retry_delay)
        except subprocess.CalledProcessError as e:
            if DEBUG:
                print(f"Attempt {attempt+1}/{max_retries}: Error checking {iface} status: {e.stderr}")
            time.sleep(retry_delay)
        except Exception as e:
            if DEBUG: print(f"Attempt {attempt+1}/{max_retries}: General error checking {iface} status: {e}")
            time.sleep(retry_delay)

    if not interface_up_and_configured:
        print(f"{RED}ERROR: Failed to bring up and configure interface {iface} after {max_retries} attempts.{RESET}")
        # print("This will likely cause subsequent tests to fail.") # Already printed by original
    
    return interface_up_and_configured

# Add loopbacks
def add_loopbacks(m1, m2, client, state): # Added 'state' parameter
    """
    Create dummy loopback interfaces for each subnet.
    
    This function creates three dummy interfaces:
    - dummy_mgmt1: For the NSB subnet
    - dummy_mgmt2: For the sensor subnet
    - dummy_client: For the client subnet
    
    Each interface is assigned the first IP address in its respective subnet.
    
    Args:
        m1: NSB subnet in CIDR notation (e.g., "192.168.10.0/24")
        m2: Sensor subnet in CIDR notation
        client: Client subnet in CIDR notation
        state: The main state dictionary to record added loopback IPs for cleanup.
    """
    if DEBUG: print("Adding loopback aliases on lo0 for macOS...")
    run_cmd(['ifconfig', 'lo0', 'up'], check=False) # Ensure lo0 is up

    if 'loopback_ips_added' not in state:
        state['loopback_ips_added'] = [] # Ensure the list exists in the state dictionary

    # We will append directly to state['loopback_ips_added']
    # local_added_ips = [] # No longer need a separate local list for this

    for name, subnet_cidr in [('mgmt1', m1), ('mgmt2', m2), ('client', client)]:
        try:
            net = ipaddress.IPv4Network(subnet_cidr)
            # Use the first usable IP address (network_address + 1)
            # Basic check: ensure subnet is larger than /31 for .1 to be valid host
            if net.num_addresses < 4 and net.prefixlen < 31: # /31 allows .0 and .1, /32 only one.
                 print(f"{RED}Error: Subnet {subnet_cidr} for {name} is too small to reliably use the .1 address. Skipping alias.{RESET}")
                 continue

            addr_to_alias = str(net.network_address + 1)
            # Check if calculated .1 is actually in the host range (handles /31 case)
            if ipaddress.IPv4Address(addr_to_alias) not in net.hosts():
                 print(f"{RED}Error: Address {addr_to_alias} (.1) is not a valid host address in subnet {subnet_cidr} for {name}. Skipping alias.{RESET}")
                 continue

            alias_netmask = str(net.netmask)

            if DEBUG:
                print(f'Aliasing {addr_to_alias} netmask {alias_netmask} on lo0 for {name}')
            
            ifconfig_lo0_out = run_cmd(['ifconfig', 'lo0'], capture_output=True, text=True).stdout
            # Check if the IP is already aliased to avoid errors / duplicate entries in our tracking
            already_exists = False
            for existing_ip_line in ifconfig_lo0_out.splitlines():
                if existing_ip_line.strip().startswith(f'inet {addr_to_alias} '):
                    already_exists = True
                    break
            
            if not already_exists:
                run_cmd(['ifconfig', 'lo0', 'inet', addr_to_alias, 'netmask', alias_netmask, 'alias'], check=True)
                if addr_to_alias not in state['loopback_ips_added']: # Avoid duplicates if somehow added externally
                    state['loopback_ips_added'].append(addr_to_alias)
            elif DEBUG:
                print(f"  Alias {addr_to_alias} already exists on lo0 or was already tracked.")
            
        except ValueError as e:
            print(f"{RED}Error processing subnet {subnet_cidr} for {name}: {e}{RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{RED}Error adding alias for {name} ({addr_to_alias}): {e.stderr}{RESET}")
        except Exception as e:
            print(f"{RED}Unexpected error in add_loopbacks for {name}: {e}{RESET}")
    
    # IPs are now directly added to state['loopback_ips_added']
    if DEBUG and state.get('loopback_ips_added'): # Check if key exists and list is not empty
        print(f"  Loopback IPs currently tracked in state: {state['loopback_ips_added']}")


# OSPF Hello sniff
def sniff_ospf_hello(iface, timeout=60):
    """
    Sniff for OSPF Hello packets on the specified interface.
    
    This function waits for an OSPF Hello packet on the specified interface
    and extracts the source IP, area, hello interval, and dead interval.
    
    Args:
        iface: The network interface to sniff on
        timeout: Maximum time to wait for an OSPF Hello packet in seconds (default: 60)
        
    Returns:
        tuple: (source_ip, area, hello_interval, dead_interval)
        
    Raises:
        SystemExit: If no OSPF Hello packet is received within the timeout
    """
    # This function is OSPF specific and will be removed for macOS compatibility.
    # For now, returning dummy values or raising an error if called.
    print(f'\n{RED}OSPF functionality (sniff_ospf_hello) is not supported on macOS in this script.{RESET}')
    # sys.exit(1) # Or return dummy values if the main flow is adjusted
    return "0.0.0.0", "0.0.0.0", 0, 0 # Dummy values

# Add floating static default
def configure_static_route(gateway, iface):
    """
    Configure a static default route and verify it was added successfully.
    
    Args:
        gateway: Gateway IP address
        iface: Interface name
        
    Returns:
        bool: True if route was added successfully, False otherwise
    """
    if DEBUG:
        print(f"\nConfiguring static default route via {gateway} on {iface} (macOS)...")
    
    # Ensure interface is up first
    try:
        run_cmd(['ifconfig', iface, 'up'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"{RED}Failed to ensure {iface} is up before adding route: {e.stderr}{RESET}")
        # return False # Decide if this is fatal

    # Delete existing default route(s) first to avoid conflicts.
    # `route delete default` might need to be run multiple times if there are several.
    if DEBUG: print("  Attempting to delete existing default routes...")
    for _ in range(3): # Try a few times
        run_cmd(['route', '-n', 'delete', 'default'], check=False, capture_output=True)

    # Try to add the new default route
    # macOS `route add default <gateway>` doesn't typically use metrics like Linux.
    # The -ifp flag can associate it with an interface but is often not needed if gateway is specific.
    cmd_add = ['route', '-n', 'add', 'default', gateway]
    # cmd_add_iface = ['route', '-n', 'add', 'default', gateway, '-ifp', iface] # Alternative if needed

    try:
        run_cmd(cmd_add, check=True)
        if DEBUG: print(f"  Attempted to add default route: {' '.join(cmd_add)}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}  Failed to add default route via {gateway}: {e.stderr}{RESET}")
        # Try with interface if the simple one fails
        # if DEBUG: print(f"  Retrying with interface specified: {' '.join(cmd_add_iface)}")
        # try:
        #     run_cmd(cmd_add_iface, check=True)
        # except subprocess.CalledProcessError as e2:
        #     print(f"{RED}  Also failed to add default route via {gateway} with -ifp {iface}: {e2.stderr}{RESET}")
        #     return False # Failed to add route

    # Verify the route was added
    max_retries = 5
    retry_delay = 2
    route_added = False
    
    for attempt in range(max_retries):
        try:
            route_output = run_cmd(['netstat', '-nr', '-f', 'inet'], capture_output=True, text=True, check=True).stdout
            # Check for "default   <gateway>"
            if re.search(rf"^(default|0\.0\.0\.0/0)\s+{re.escape(gateway)}", route_output, re.MULTILINE):
                if DEBUG:
                    print(f"Static default route via {gateway} successfully verified.")
                route_added = True
                break
            else:
                if DEBUG:
                    print(f"Attempt {attempt+1}/{max_retries}: Static route via {gateway} not found in netstat output.")
                    # print(f"  Current default routes:\n{route_output}") # Can be verbose
                # Re-attempt adding if not found, in case it was removed by something else
                if attempt < max_retries -1: # Don't re-add on last attempt
                    run_cmd(cmd_add, check=False) # Re-try adding
        except subprocess.CalledProcessError as e:
            if DEBUG: print(f"  Error checking routes (attempt {attempt+1}): {e.stderr}")
        
        if attempt < max_retries - 1:
            if DEBUG: print(f"  Waiting {retry_delay} seconds before checking route again...")
            time.sleep(retry_delay)
    
    if not route_added:
        print(f"{RED}ERROR: Failed to add static default route via {gateway} after {max_retries} attempts.{RESET}")
        print("This will likely cause subsequent tests to fail.")
        print("Continuing anyway, but expect failures...")
    
    return route_added

# Connectivity tests with DNS fallback logic
def run_tests(iface, ip_addr, mgmt1, client_subnet, dhcp_servers, radius_servers, secret, user, pwd, run_dhcp, run_radius, custom_dns_servers=None, custom_ntp_servers=None, test_results=None):
    """
    Run a comprehensive suite of network connectivity tests.
    
    This function tests:
    - DNS resolution and connectivity
    - DHCP relay functionality
    - RADIUS authentication
    - NTP synchronization
    - HTTPS connectivity
    - SSL certificate validation
    - UDP connectivity to guest access points
    
    Args:
        iface: The network interface to use for tests
        ip_addr: The IP address of the interface
        mgmt1: NSB subnet in CIDR notation
        client_subnet: Client subnet in CIDR notation
        dhcp_servers: List of DHCP server IP addresses
        radius_servers: List of RADIUS server IP addresses
        secret: RADIUS shared secret
        user: RADIUS username
        pwd: RADIUS password
        run_dhcp: Whether to run DHCP tests
        run_radius: Whether to run RADIUS tests
        custom_dns_servers: Optional list of custom DNS servers to test
        custom_ntp_servers: Optional list of custom NTP servers to test
        test_results: Optional list to append test results to
        
    Returns:
        list: A list of tuples containing test results (test_name, result)
    """
    # Initialize empty lists if None
    custom_dns_servers = custom_dns_servers or []
    custom_ntp_servers = custom_ntp_servers or []
    # Dictionary to store test results for summary
    if test_results is None:
        test_results = []
    # Set initial DNS
    dns_servers = ['8.8.8.8', '8.8.4.4']
    
    # Write DNS servers to resolv.conf
    def write_resolv(servers):
        with open('/etc/resolv.conf','w') as f:
            for s in servers:
                f.write(f'nameserver {s}\n')
    write_resolv(dns_servers)
    conf.route.resync()
    
    # Initial connectivity
    ping_ok = False
    print(f'\nInitial Ping Tests from {ip_addr} (macOS using ping -S):')
    
    # Test default DNS servers with retry logic
    for tgt in dns_servers:
        ping_cmd = ['ping', '-c', '2', '-S', ip_addr, tgt]
        # First attempt
        r = run_cmd(ping_cmd, capture_output=True)
        result = r.returncode == 0
        
        # If first attempt fails, retry once more
        if not result:
            print(f'Ping {tgt} from {ip_addr}: {RED}Fail{RESET} (First attempt)')
            print(f'Retrying ping to {tgt}...')
            ping_cmd_retry = ['ping', '-c', '3', '-S', ip_addr, tgt]
            r = run_cmd(ping_cmd_retry, capture_output=True)
            result = r.returncode == 0
        
        print(f'Ping {tgt} from {ip_addr}: ' + (GREEN+'Success'+RESET if result else RED+'Fail (After retry)'+RESET))
        test_results.append((f'Initial Ping {tgt} from {ip_addr}', result))
        ping_ok |= result
    
    # Test custom DNS servers if provided (with retry logic)
    if custom_dns_servers:
        print(f'\nCustom DNS Server Ping Tests from {ip_addr} (macOS using ping -S):')
        custom_ping_ok = False
        for tgt in custom_dns_servers:
            ping_cmd = ['ping', '-c', '2', '-S', ip_addr, tgt]
            # First attempt
            r = run_cmd(ping_cmd, capture_output=True)
            result = r.returncode == 0
            
            # If first attempt fails, retry once more
            if not result:
                print(f'Ping {tgt} from {ip_addr}: {RED}Fail{RESET} (First attempt)')
                print(f'Retrying ping to {tgt}...')
                ping_cmd_retry = ['ping', '-c', '3', '-S', ip_addr, tgt]
                r = run_cmd(ping_cmd_retry, capture_output=True)
                result = r.returncode == 0
            
            print(f'Ping {tgt} from {ip_addr}: ' + (GREEN+'Success'+RESET if result else RED+'Fail (After retry)'+RESET))
            test_results.append((f'Initial Ping Custom DNS {tgt} from {ip_addr}', result))
            custom_ping_ok |= result
        
        # Update ping_ok to include custom DNS server ping results
        ping_ok |= custom_ping_ok


    print(f'\nInitial DNS Tests from {ip_addr} (@ ' + ', '.join(dns_servers) + '):')
    for d in dns_servers:
        r = run_cmd(['dig', f'@{d}', '-b', ip_addr, 'www.google.com', '+short'], capture_output=True, text=True)
        ok = (r.returncode==0 and bool(r.stdout.strip()))
        print(f'DNS @{d} from {ip_addr}: ' + (GREEN+'Success'+RESET if ok else RED+'Fail'+RESET))
        test_results.append((f'Initial DNS @{d} from {ip_addr}', ok))

    # Custom DNS tests from iface interface if provided
    if custom_dns_servers:
        print(f'\n=== Custom DNS tests from {ip_addr} ===')
        for d in custom_dns_servers:
            r = run_cmd(['dig', f'@{d}', '-b', ip_addr, 'www.google.com', '+short'], capture_output=True, text=True)
            ok = (r.returncode==0 and bool(r.stdout.strip()))
            print(f'Custom DNS @{d} from {ip_addr}: ' + (GREEN+'Success'+RESET if ok else RED+'Fail'+RESET))
            test_results.append((f'Custom DNS @{d} from {ip_addr}', ok))
        
        # If custom DNS servers are provided and successful, use them
        successful_custom_dns = []
        for d in custom_dns_servers:
            r = run_cmd(['dig', f'@{d}', '-b', ip_addr, 'www.google.com', '+short'], capture_output=True, text=True)
            if r.returncode == 0 and bool(r.stdout.strip()):
                successful_custom_dns.append(d)
        
        if successful_custom_dns:
            print(f"\nUsing successful custom DNS servers: {', '.join(successful_custom_dns)}")
            dns_servers = successful_custom_dns
            write_resolv(dns_servers)
            # Skip the prompt for DNS servers if we're using custom ones
            if not args.config:  # Only in interactive mode
                print("Using custom DNS servers instead of prompting for new ones.")
        else:
            # If no custom DNS servers were successful, prompt for new ones
            new_dns = prompt_nonempty('Enter DNS server IP(s) (comma-separated): ')
            dns_servers = [s.strip() for s in new_dns.split(',')]
            write_resolv(dns_servers)
    else:
        # No custom DNS servers provided, prompt for new ones
        new_dns = prompt_nonempty('Enter DNS server IP(s) (comma-separated): ')
        dns_servers = [s.strip() for s in new_dns.split(',')]
        write_resolv(dns_servers)

    if not ping_ok:
        print(f"\n{RED}ERROR: Initial connectivity tests beyond local network have failed.{RESET}")
        print(f"{RED}All DNS servers (default and custom) are unreachable.{RESET}")
        print(f"{RED}Please validate your routing configuration and try again.{RESET}")
        print(f"{RED}Terminating tests...{RESET}")
        sys.exit(1)

    # Full suite
    print(f'\nFull Test Suite:')
    
    # Get the IP address of the mgmt1 loopback alias (using the .1 address)
    mgmt1_net = ipaddress.IPv4Network(mgmt1)
    mgmt1_ip = str(mgmt1_net.network_address + 1)
    # Quick check if .1 is valid for mgmt1 subnet used in tests
    if ipaddress.IPv4Address(mgmt1_ip) not in mgmt1_net.hosts():
         print(f"{RED}ERROR: Calculated mgmt1 IP {mgmt1_ip} (.1) is not valid in subnet {mgmt1}. Cannot proceed with tests sourcing from this IP.{RESET}")
         sys.exit(1)

    print(f"Using mgmt1 loopback alias with IP {mgmt1_ip} as source for tests")
    
    # Verify the loopback alias IP is configured and working
    if DEBUG:
        print(f"Verifying {mgmt1_ip} can reach external targets...")
    max_retries = 5
    retry_delay = 2
    loopback_working = False
    
    for attempt in range(max_retries):
        if DEBUG:
            print(f"Attempt {attempt+1}/{max_retries}: Testing connectivity from {mgmt1_ip} to {dns_servers[0]} (macOS using ping -S)...")
        # Ping the first DNS server as a target for loopback connectivity check
        target_for_loopback_check = dns_servers[0] if dns_servers else "8.8.8.8" # Fallback if no DNS servers
        ping_cmd_loopback = ['ping', '-c', '2', '-S', mgmt1_ip, target_for_loopback_check]
        ping_result = run_cmd(ping_cmd_loopback, capture_output=True)
        if ping_result.returncode == 0:
            if DEBUG:
                print(f"Connectivity from {mgmt1_ip} to {target_for_loopback_check}: {GREEN}Success{RESET}")
            loopback_working = True
            break
        else:
            if DEBUG:
                print(f"Connectivity from {mgmt1_ip}: {RED}Fail{RESET}")
                print(f"Waiting {retry_delay} seconds before retrying...")
            time.sleep(retry_delay)
    
    if not loopback_working:
        print(f"\n{RED}ERROR: Could not establish connectivity from the dummy loopback interface {mgmt1_ip}.{RESET}")
        print(f"{RED}Please try the test again after resolving network issues.{RESET}")
        print(f"{RED}Terminating tests...{RESET}")
        return test_results  # Return early with the tests we've done so far

    # Ping tests
    print(f'\n=== Ping tests from {mgmt1_ip} (macOS using ping -S) ===')
    for tgt in dns_servers:
        ping_cmd_mgmt1 = ['ping', '-c', '4', '-S', mgmt1_ip, tgt]
        r = run_cmd(ping_cmd_mgmt1, capture_output=True, text=True)
        result = r.returncode == 0
        print(f'Ping {tgt} from {mgmt1_ip}: ' + (GREEN+'Success'+RESET if result else RED+'Fail'+RESET))
        test_results.append((f'Ping {tgt} from {mgmt1_ip}', result))
    
    # DNS tests
    print(f'\n=== DNS tests ===')
    for d in dns_servers:
        r = run_cmd(['dig', f'@{d}', '-b', mgmt1_ip, 'www.google.com', '+short'], capture_output=True, text=True)
        ok = (r.returncode==0 and bool(r.stdout.strip()))
        print(f'DNS @{d} from {mgmt1_ip}: ' + (GREEN+'Success'+RESET if ok else RED+'Fail'+RESET))
        test_results.append((f'DNS @{d} from {mgmt1_ip}', ok))
    
    # DHCP relay with ping pre-check - using dhcppython library
    if run_dhcp:
        print(f'\n=== DHCP tests (L3 relay) ===')
        # Use the first IP of the client subnet as the helper IP (giaddr)
        helper_ip = str(ipaddress.IPv4Network(client_subnet).network_address+1)
        print(f"Using client subnet first IP {helper_ip} as DHCP relay agent (giaddr)")
        
        # For the source IP, we should use the helper IP address (giaddr)
        # This is what the server will see as the source of the packet
        source_ip = helper_ip
        if DEBUG:
            print(f"Using helper IP {source_ip} as source IP for DHCP packets")
        
        for srv in dhcp_servers:
            p = run_cmd(['ping', '-c', '5', srv], capture_output=True)
            if p.returncode != 0:
                result = False
                print(f'DHCP relay to {srv}: {RED}Fail (unreachable){RESET}')
                test_results.append((f'DHCP relay to {srv}', result))
                continue
            
            # Get the MAC address for the main interface (macOS way)
            iface_mac = None
            try:
                ifconfig_out = run_cmd(['ifconfig', iface], capture_output=True, text=True, check=True).stdout
                match = re.search(r'ether\s+([0-9a-fA-F:]{17})', ifconfig_out)
                if match:
                    iface_mac = match.group(1)
                    if DEBUG: print(f"  Found MAC {iface_mac} for {iface}")
            except subprocess.CalledProcessError as e:
                if DEBUG: print(f"  Error getting MAC for {iface}: {e.stderr}")
            except Exception as e_gen:
                 if DEBUG: print(f"  Unexpected error getting MAC for {iface}: {e_gen}")

            if not iface_mac:
                print(f"Warning: Could not determine MAC address for {iface} using ifconfig, using random MAC")
                iface_mac = dhcp_utils.random_mac()
                
            # Create a random client MAC address
            client_mac = dhcp_utils.random_mac()
            
            # Using dhcppython for DHCP testing

            if DEBUG:
                print(f"DHCP Test Details:")
                print(f"  Interface: {iface} (MAC: {iface_mac})")
                print(f"  Source IP: {source_ip}")
                print(f"  Destination IP: {srv}")
                print(f"  Client MAC: {client_mac}")
            
            try:
                # Create DHCP client using the main interface
                if DEBUG:
                    print(f"Creating DHCP client on {iface} interface...")
                c = dhcp_client.DHCPClient(
                    iface,
                    send_from_port=67,  # Server port (for relay)
                    send_to_port=67     # Server port
                )
                
                # Create a list of DHCP options
                if DEBUG:
                    print(f"Setting up DHCP options...")
                options_list = dhcp_options.OptionList([
                    # Add standard options
                    dhcp_options.options.short_value_to_object(60, "nile-readiness-test"),  # Class identifier
                    dhcp_options.options.short_value_to_object(12, socket.gethostname()),   # Hostname
                    # Parameter request list - request common options
                    dhcp_options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43])
                ])
                
                if DEBUG:
                    print(f"Attempting to get DHCP lease from {srv}...")
                # Set broadcast=False for unicast to specific server
                # Set server to the DHCP server IP
                try:
                    lease = c.get_lease(
                        client_mac,
                        broadcast=False,
                        options_list=options_list,
                        server=srv,
                        relay=helper_ip
                    )
                    
                    # If we get here, we got a lease
                    if DEBUG:
                        print(f"\nSuccessfully obtained DHCP lease!")
                        print(f"DEBUG: Lease details:")
                        print(f"  Your IP: {lease.ack.yiaddr}")
                        print(f"  Server IP: {lease.ack.siaddr}")
                        print(f"  Gateway: {lease.ack.giaddr}")
                        print(f"  Options: {lease.ack.options}")
                    
                    result = True
                    print(f'DHCP relay to {srv}: ' + GREEN+'Success'+RESET)
                    test_results.append((f'DHCP relay to {srv}', result))
                except Exception as e:
                    print(f"Error during DHCP lease request: {e}")
                    if DEBUG:
                        import traceback
                        traceback.print_exc()
                    result = False
                    print(f'DHCP relay to {srv}: ' + RED+'Fail'+RESET)
                    test_results.append((f'DHCP relay to {srv}', result))
                
                
            except Exception as e:
                print(f"Error during DHCP test: {e}")
                if DEBUG:
                    import traceback
                    traceback.print_exc()
                result = False
                print(f'DHCP relay to {srv}: ' + RED+'Fail'+RESET)
                test_results.append((f'DHCP relay to {srv}', result))
    else:
        print('\nSkipping DHCP tests')

    # RADIUS with ping pre-check
    if run_radius:
        print(f'\n=== RADIUS tests ===')
        for srv in radius_servers:
            p = run_cmd(['ping', '-c', '1', srv], capture_output=True)
            if p.returncode != 0:
                result = False
                print(f'RADIUS {srv}: {RED}Fail (unreachable){RESET}')
                test_results.append((f'RADIUS {srv}', result))
                continue
            cmd = (f'echo "User-Name={user},User-Password={pwd}" '
                  f'| radclient -x -s {srv}:1812 auth {secret}')
            res = run_cmd(cmd, shell=True, capture_output=True, text=True)
            result = res.returncode == 0
            print(f'RADIUS {srv}: ' + (GREEN+'Success'+RESET if result else RED+'Fail'+RESET))
            test_results.append((f'RADIUS {srv}', result))
    else:
        print('\nSkipping RADIUS tests')

    # NTP tests from main interface
    print(f'\n=== NTP tests from main interface ({ip_addr}) ===')
    if ntplib:
        for ntp_server_host in ('time.google.com', 'pool.ntp.org'):
            result = test_ntp_with_ntplib(ntp_server_host, source_ip=ip_addr)
            print(f'NTP (ntplib) {ntp_server_host} from {ip_addr}: ' + (GREEN+'Success'+RESET if result else RED+'Fail'+RESET))
            test_results.append((f'NTP (ntplib) {ntp_server_host} from {ip_addr}', result))
        
        if custom_ntp_servers:
            print(f'\n=== Custom NTP tests from main interface ({ip_addr}) ===')
            for ntp_server_host in custom_ntp_servers:
                result = test_ntp_with_ntplib(ntp_server_host, source_ip=ip_addr)
                print(f'Custom NTP (ntplib) {ntp_server_host} from {ip_addr}: ' + (GREEN+'Success'+RESET if result else RED+'Fail'+RESET))
                test_results.append((f'Custom NTP (ntplib) {ntp_server_host} from {ip_addr}', result))
    else:
        print("  Skipping NTP tests because ntplib is not available.")

    # NTP tests from mgmt1
    print(f'\n=== NTP tests from mgmt1 ({mgmt1_ip}) ===')
    if ntplib:
        for ntp_server_host in ('time.google.com', 'pool.ntp.org'):
            result = test_ntp_with_ntplib(ntp_server_host, source_ip=mgmt1_ip)
            print(f'NTP (ntplib) {ntp_server_host} from {mgmt1_ip}: ' + (GREEN+'Success'+RESET if result else RED+'Fail'+RESET))
            test_results.append((f'NTP (ntplib) {ntp_server_host} from {mgmt1_ip}', result))

        if custom_ntp_servers:
            print(f'\n=== Custom NTP tests from mgmt1 ({mgmt1_ip}) ===')
            for ntp_server_host in custom_ntp_servers:
                result = test_ntp_with_ntplib(ntp_server_host, source_ip=mgmt1_ip)
                print(f'Custom NTP (ntplib) {ntp_server_host} from {mgmt1_ip}: ' + (GREEN+'Success'+RESET if result else RED+'Fail'+RESET))
                test_results.append((f'Custom NTP (ntplib) {ntp_server_host} from {mgmt1_ip}', result))
    else:
        print("  Skipping NTP tests because ntplib is not available.")

    # HTTPS and SSL Certificate tests
    print(f'\n=== HTTPS and SSL Certificate tests ===')
    
    # Test HTTPS/TLS connectivity for Nile Cloud from main interface using openssl s_client
    print(f'Testing HTTPS/TLS connectivity for {NILE_HOSTNAME} from {ip_addr}...')
    https_conn_ok_nile_main = test_tls_connectivity_openssl(NILE_HOSTNAME, source_ip=ip_addr)
    print(f'HTTPS/TLS {NILE_HOSTNAME} from {ip_addr}: ' + (GREEN+'Success'+RESET if https_conn_ok_nile_main else RED+'Fail'+RESET))
    test_results.append((f'HTTPS/TLS Connectivity {NILE_HOSTNAME} from {ip_addr}', https_conn_ok_nile_main))

    # Test HTTPS/TLS connectivity for Nile Cloud from mgmt1 using openssl s_client
    print(f'\nTesting HTTPS/TLS connectivity for {NILE_HOSTNAME} from {mgmt1_ip}...')
    https_conn_ok_nile_mgmt1 = test_tls_connectivity_openssl(NILE_HOSTNAME, source_ip=mgmt1_ip)
    print(f'HTTPS/TLS {NILE_HOSTNAME} from {mgmt1_ip}: ' + (GREEN+'Success'+RESET if https_conn_ok_nile_mgmt1 else RED+'Fail'+RESET))
    test_results.append((f'HTTPS/TLS Connectivity {NILE_HOSTNAME} from {mgmt1_ip}', https_conn_ok_nile_mgmt1))
    
    # Now check the SSL certificate (this uses openssl s_client and dig, and is more thorough)
    print(f'\nChecking SSL certificate details for {NILE_HOSTNAME}...')
    # Use dig to resolve the hostname to IP addresses
    r = run_cmd(['dig', NILE_HOSTNAME, '+short'], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        nile_ips = r.stdout.strip().split('\n')
        print(f"\nResolved {NILE_HOSTNAME} to: {', '.join(nile_ips)}")
        nile_ssl_success = False
        for ip in nile_ips:
            if check_ssl_certificate(ip, NILE_HOSTNAME, "Nile Global Inc."):
                nile_ssl_success = True
                print(f"SSL certificate for {NILE_HOSTNAME}: {GREEN}Success{RESET}")
                break
            else:
                print(f"SSL certificate for {NILE_HOSTNAME} (IP: {ip}): {RED}Fail{RESET}")
        test_results.append((f"SSL Certificate for {NILE_HOSTNAME}", nile_ssl_success))
    else:
        print(f"Could not resolve {NILE_HOSTNAME} for SSL check")
        test_results.append((f"SSL Certificate for {NILE_HOSTNAME}", False))
    
    # Test HTTPS/TLS connectivity for Amazon S3 from main interface
    print(f'\nTesting HTTPS/TLS connectivity for {S3_HOSTNAME} from {ip_addr}...')
    https_conn_ok_s3_main = test_tls_connectivity_openssl(S3_HOSTNAME, source_ip=ip_addr)
    print(f'HTTPS/TLS {S3_HOSTNAME} from {ip_addr}: ' + (GREEN+'Success'+RESET if https_conn_ok_s3_main else RED+'Fail'+RESET))
    test_results.append((f'HTTPS/TLS Connectivity {S3_HOSTNAME} from {ip_addr}', https_conn_ok_s3_main))
    
    # Test HTTPS/TLS connectivity for Amazon S3 from mgmt1
    print(f'\nTesting HTTPS/TLS connectivity for {S3_HOSTNAME} from {mgmt1_ip}...')
    https_conn_ok_s3_mgmt1 = test_tls_connectivity_openssl(S3_HOSTNAME, source_ip=mgmt1_ip)
    print(f'HTTPS/TLS {S3_HOSTNAME} from {mgmt1_ip}: ' + (GREEN+'Success'+RESET if https_conn_ok_s3_mgmt1 else RED+'Fail'+RESET))
    test_results.append((f'HTTPS/TLS Connectivity {S3_HOSTNAME} from {mgmt1_ip}', https_conn_ok_s3_mgmt1))
    
    # Now check the SSL certificate
    print(f'\nChecking SSL certificate for {S3_HOSTNAME}...')
    # Use dig to resolve the hostname to IP addresses
    r = run_cmd(['dig', S3_HOSTNAME, '+short'], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        s3_ips = r.stdout.strip().split('\n')
        print(f"\nResolved {S3_HOSTNAME} to: {', '.join(s3_ips)}")
        s3_ssl_success = False
        # Only test the first 2 IPs for S3
        for ip in s3_ips[:2]:
            if check_ssl_certificate(ip, S3_HOSTNAME, "Amazon"):
                s3_ssl_success = True
                print(f"SSL certificate for {S3_HOSTNAME}: {GREEN}Success{RESET}")
                break
            else:
                print(f"SSL certificate for {S3_HOSTNAME} (IP: {ip}): {RED}Fail{RESET}")
        test_results.append((f"SSL Certificate for {S3_HOSTNAME}", s3_ssl_success))
    else:
        print(f"Could not resolve {S3_HOSTNAME} for SSL check")
        test_results.append((f"SSL Certificate for {S3_HOSTNAME}", False))
    
    # Test HTTPS/TLS connectivity for Nile Secure from main interface
    NILESECURE_HOSTNAME = "u1.nilesecure.com" 
    print(f'\nTesting HTTPS/TLS connectivity for {NILESECURE_HOSTNAME} from {ip_addr}...')
    https_conn_ok_secure_main = test_tls_connectivity_openssl(NILESECURE_HOSTNAME, source_ip=ip_addr)
    print(f'HTTPS/TLS {NILESECURE_HOSTNAME} from {ip_addr}: ' + (GREEN+'Success'+RESET if https_conn_ok_secure_main else RED+'Fail'+RESET))
    test_results.append((f'HTTPS/TLS Connectivity {NILESECURE_HOSTNAME} from {ip_addr}', https_conn_ok_secure_main))
    
    # Test HTTPS/TLS connectivity for Nile Secure from mgmt1
    print(f'\nTesting HTTPS/TLS connectivity for {NILESECURE_HOSTNAME} from {mgmt1_ip}...')
    https_conn_ok_secure_mgmt1 = test_tls_connectivity_openssl(NILESECURE_HOSTNAME, source_ip=mgmt1_ip)
    print(f'HTTPS/TLS {NILESECURE_HOSTNAME} from {mgmt1_ip}: ' + (GREEN+'Success'+RESET if https_conn_ok_secure_mgmt1 else RED+'Fail'+RESET))
    test_results.append((f'HTTPS/TLS Connectivity {NILESECURE_HOSTNAME} from {mgmt1_ip}', https_conn_ok_secure_mgmt1))
    
    '''
    ###### Test is not working #####
    # UDP Connectivity Check for Guest Access
    print(f'\n=== UDP Connectivity Check for Guest Access ===')
    guest_success = False
    
    for guest_ip_target in GUEST_IPS:
        print(f"Testing UDP connectivity to {guest_ip_target}:{UDP_PORT} from {ip_addr}...")
        # Pass ip_addr (main test interface IP) as the source_ip for the netcat test
        if check_udp_connectivity_netcat(guest_ip_target, UDP_PORT, source_ip=ip_addr):
            guest_success = True
            print(f"UDP connectivity to {guest_ip_target}:{UDP_PORT} from {ip_addr}: {GREEN}Success{RESET}")
            break # Success on first reachable guest IP is enough
        else:
            print(f"UDP connectivity to {guest_ip_target}:{UDP_PORT} from {ip_addr}: {RED}Fail{RESET}")
    
    test_results.append((f"UDP Connectivity Check for Guest Access (from {ip_addr})", guest_success))
    '''
    
    return test_results

# Print test summary
def print_test_summary(test_results):
    """
    Print a summary of all test results.
    
    This function:
    - Filters out tests that shouldn't be included in the summary
    - Prints each test name and its result (Success/Fail)
    - Calculates and prints the overall success rate
    
    Args:
        test_results: List of tuples containing test results (test_name, result)
    """
    print("\n=== Test Summary ===")
    success_count = 0
    total_count = 0
    
    # Filter out tests that shouldn't be included in the summary
    excluded_tests = ["Static Default Route Configuration"]
    
    for test_name, result in test_results:
        # Skip excluded tests
        if test_name in excluded_tests:
            continue
            
        status = GREEN + "Success" + RESET if result else RED + "Fail" + RESET
        print(f"{test_name}: {status}")
        total_count += 1
        if result:
            success_count += 1
    
    success_rate = (success_count / total_count) * 100 if total_count > 0 else 0
    print(f"\nOverall: {success_count}/{total_count} tests passed ({success_rate:.1f}%)")

# Main flow
def main():
    """
    Main execution flow of the Nile Readiness Test.
    
    This function:
    1. Gathers configuration parameters from file or user input
    2. Records the original state of the network interface
    3. Configures the interface and adds loopback interfaces
    4. Sets up a static default route
    5. Configures OSPF routing
    6. Runs connectivity tests (DNS, DHCP, RADIUS, NTP, HTTPS, UDP)
    7. Restores the original state of the system
    8. Prints a summary of test results
    """
    # Get user input from config file or interactive prompts
    (test_iface, ip_addr, netmask, gateway, mgmt_interface,
     mgmt1, mgmt2, client_subnet,
     dhcp_servers, radius_servers, secret, username, password,
     run_dhcp, run_radius, custom_dns_servers, custom_ntp_servers) = get_user_input(args.config)
    
    # Print summary of custom DNS and NTP servers if provided
    if custom_dns_servers:
        print(f"\nWill test custom DNS servers: {', '.join(custom_dns_servers)}")
    if custom_ntp_servers:
        print(f"\nWill test custom NTP servers: {', '.join(custom_ntp_servers)}")

    # Record the original state of the interface
    state = record_state(test_iface) # state will be used to track loopbacks too
    
    try:
        # Initial cleanup: Restore to original state before applying new config.
        # This helps ensure a clean slate if the script exited prematurely before.
        # if DEBUG: print("\nPerforming initial cleanup by restoring state...")
        #  restore_state(test_iface, state) # state already includes loopback_ips_added list
        #  time.sleep(2) # Give a moment for system to settle after restore

        # Configure the interface (includes validation and retry logic)
        if DEBUG: print("\nConfiguring main test interface...")
        interface_up = configure_interface(test_iface, ip_addr, netmask, mgmt_interface)
        
        # Add loopbacks (aliases on lo0 for macOS), pass state to track them
        if DEBUG: print("\nAdding loopback aliases...")
        add_loopbacks(mgmt1, mgmt2, client_subnet, state) # Pass state here
        
        # Configure static route and verify it was added successfully
        if DEBUG: print("\nConfiguring static default route...")
        # prefix = ipaddress.IPv4Network(f'0.0.0.0/{netmask}').prefixlen # prefix not directly used by macOS route command
        route_added = configure_static_route(gateway, test_iface)
        
        # Add the route status to the test results
        test_results = []
        test_results.append(("Static Default Route Configuration", route_added))

        # Update scapy's routing table
        conf.route.resync()
        
        # Sniff for OSPF Hello packets (Detection only on macOS)
        ospf_detected = detect_ospf_hello(test_iface)
        test_results.append(("OSPF Hello Detection", ospf_detected))
        
        # Configure OSPF - Skipped for macOS
        # configure_ospf(...) 
        
        # Check OSPF status - Skipped for macOS
        # show_ospf_status()

        # Run connectivity tests with the existing test_results list
        # Note: run_tests now starts immediately after OSPF detection attempt
        test_results = run_tests(test_iface, ip_addr, mgmt1, client_subnet, dhcp_servers, radius_servers, secret, username, password, run_dhcp, run_radius, custom_dns_servers, custom_ntp_servers, test_results)
    
    finally:
        # Restore the original state
        print('\nRestoring original state...')
        restore_state(test_iface, state)
        
        # Print test summary after restoring state
        if 'test_results' in locals():
            print_test_summary(test_results)

if __name__=='__main__':
    if os.geteuid()!=0:
        print('Must run as root')
        sys.exit(1)
    
    main()
