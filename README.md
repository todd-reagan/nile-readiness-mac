# Nile Readiness Test (NRT)

This tool helps test network connectivity and features required for Nile Connect, including Geneve protocol support.

## Features

- Geneve protocol testing (UDP port 6081)
  - Kernel tunnel creation method
  - Scapy packet method
  - Basic UDP connectivity fallback

## Requirements

- Python 3.6+
- Scapy (with Geneve module support)
- Root/sudo privileges (for network operations)
- Netcat (nc) for UDP connectivity testing

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/nile-readiness-test.git
   cd nile-readiness-test
   ```

2. Install required Python packages:
   ```
   pip install scapy dhcppython
   ```

## Usage

### Testing Geneve Protocol Support

Test Geneve protocol support using the main script:

```bash
# Test Geneve protocol support on a specific target
sudo ./nrt.py --geneve-test --target 145.40.90.203

# Enable debug output for more detailed information
sudo ./nrt.py --geneve-test --target 145.40.90.203 --debug

# If no target is specified, it will use the first IP from the GUEST_IPS list
sudo ./nrt.py --geneve-test
```

## How Geneve Testing Works

The Geneve testing functionality uses two methods to test if a target supports the Geneve protocol:

1. **Kernel Tunnel Method**: Attempts to create a Geneve tunnel to the target using the Linux kernel's native Geneve support.
   - Checks if the kernel supports Geneve tunnels
   - Creates a Geneve tunnel to the target
   - Assigns an IP address to the tunnel
   - Brings the tunnel up
   - Checks if the tunnel is in UP state

2. **Scapy Packet Method**: Uses Scapy to send and receive Geneve packets.
   - Sends a Geneve packet to the target
   - Sniffs for a response
   - Analyzes the response to determine if it's a Geneve packet

3. **Basic UDP Connectivity Fallback**: If both methods fail, it checks if the UDP port is open.
   - Uses netcat to check if the UDP port is open
   - Provides troubleshooting information

## Troubleshooting

- **Kernel Tunnel Method Fails**:
  - Check if your kernel supports Geneve tunnels (`modprobe geneve`)
  - Verify you have permission to create network interfaces (run as root/sudo)
  - Check network connectivity to the target

- **Scapy Packet Method Fails**:
  - Check if Scapy is installed with Geneve support
  - Verify you have permission to send raw packets (run as root/sudo)
  - Check if the interface is up and has proper IP configuration

- **Basic UDP Connectivity Fails**:
  - Check if the target is running
  - Verify there is no firewall blocking UDP traffic to port 6081
  - The target may not support Geneve protocol

## License

This project is licensed under the MIT License - see the LICENSE file for details.
