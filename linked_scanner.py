#!/usr/bin/env python3
"""
Linked ICMP Scanner - Integrates packet scanner with reverse shell
This file links everything together:
- Detects ICMP shell traffic
- Can act as a passive listener
- Monitors for active implants
- Works alongside the C2 server
"""

import socket
import struct
import time
import threading
import sys
import os
from datetime import datetime

# Import encoder if available
try:
    from encoder import XOREncoder, StealthEncoder
    ENCODER_AVAILABLE = True
except ImportError:
    ENCODER_AVAILABLE = False
    print("[!] encoder.py not found, running without encryption support")

class LinkedICMPScanner:
    def __init__(self, mode="monitor"):
        """
        mode: "monitor" - just watch for ICMP shells
              "bridge"  - monitor + relay commands
              "stealth" - passive detection only
        """
        self.mode = mode
        self.sock = None
        self.detected_implants = {}  # {ip: {"id": int, "last_seen": time, "payloads": []}}
        self.running = True
        self.alerts = []
        
        # Initialize encoder if available
        if ENCODER_AVAILABLE:
            self.encoder = XOREncoder()
            print("[+] Encryption module loaded")
        
    def create_socket(self):
        """Create raw ICMP socket for sniffing"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.sock.settimeout(1)
            print("[+] ICMP sniffer socket created")
            return True
        except PermissionError:
            print("[-] Root/Admin privileges required!")
            return False
        except Exception as e:
            print(f"[-] Socket error: {e}")
            return False
    
    def parse_icmp(self, packet):
        """Parse ICMP packet and extract relevant info"""
        try:
            # Parse IP header
            ip_header = packet[:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            protocol = iph[6]
            
            if protocol != 1:  # Not ICMP
                return None
            
            # Parse ICMP header
            icmp_start = 20
            icmp_header = packet[icmp_start:icmp_start+8]
            icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack('!BBHHH', icmp_header)
            
            # Get payload
            payload = packet[icmp_start+8:].decode('utf-8', errors='ignore').strip('\x00')
            
            return {
                "src": src_ip,
                "dst": dst_ip,
                "type": icmp_type,
                "code": icmp_code,
                "id": icmp_id,
                "seq": icmp_seq,
                "payload": payload,
                "size": len(payload),
                "timestamp": time.time()
            }
        except Exception:
            return None
    
    def is_shell_traffic(self, packet_info):
        """Detect if packet is from ICMP reverse shell"""
        payload = packet_info["payload"].lower()
        
        # Known shell indicators
        indicators = [
            "hello",
            "heartbeat",
            "ready",
            "whoami",
            "ls -la",
            "dir",
            "cmd.exe",
            "bash",
            "powershell",
            "etc/passwd",
            "c:\\users",
            "x86_64",
            "pid="
        ]
        
        # Large payloads are suspicious (normal ping has tiny payload)
        is_large = packet_info["size"] > 50
        
        # Check for indicators
        matches = [ind for ind in indicators if ind in payload.lower()]
        
        if matches or (is_large and packet_info["type"] == 8):
            return True, matches
        
        return False, []
    
    def log_implant(self, src_ip, packet_info):
        """Log detected implant activity"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if src_ip not in self.detected_implants:
            self.detected_implants[src_ip] = {
                "first_seen": timestamp,
                "last_seen": timestamp,
                "packet_count": 0,
                "icmp_id": packet_info["id"],
                "payloads": []
            }
            print(f"\n[!] NEW IMPLANT DETECTED: {src_ip}")
            print(f"    ICMP ID: {packet_info['id']}")
            print(f"    Time: {timestamp}\n")
        
        # Update stats
        implant = self.detected_implants[src_ip]
        implant["last_seen"] = timestamp
        implant["packet_count"] += 1
        
        # Store payload preview (keep last 5)
        if packet_info["payload"]:
            payload_preview = packet_info["payload"][:100].replace('\n', ' ')
            implant["payloads"].append({
                "time": timestamp,
                "payload": payload_preview,
                "size": packet_info["size"]
            })
            if len(implant["payloads"]) > 5:
                implant["payloads"].pop(0)
    
    def print_detection(self, packet_info, indicators):
        """Print detection alert with details"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        print("\n" + "🔴" * 35)
        print(f"[{timestamp}] ICMP SHELL TRAFFIC DETECTED")
        print("🔴" * 35)
        print(f"  Source:      {packet_info['src']}")
        print(f"  Destination: {packet_info['dst']}")
        print(f"  Type:        {'Echo Request' if packet_info['type'] == 8 else 'Echo Reply'}")
        print(f"  ICMP ID:     {packet_info['id']}")
        print(f"  Size:        {packet_info['size']} bytes")
        
        if indicators:
            print(f"  Indicators:  {', '.join(indicators)}")
        
        if packet_info["payload"] and len(packet_info["payload"]) > 0:
            print(f"\n  Payload preview:")
            print(f"  {packet_info['payload'][:150]}")
        
        print("🔴" * 35 + "\n")
    
    def export_report(self, filename="icmp_scan_report.txt"):
        """Export detection report to file"""
        if not self.detected_implants:
            print("[*] No implants detected, no report generated")
            return
        
        with open(filename, "w") as f:
            f.write("="*60 + "\n")
            f.write("ICMP REVERSE SHELL SCAN REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Total implants detected: {len(self.detected_implants)}\n\n")
            
            for ip, data in self.detected_implants.items():
                f.write(f"Implant: {ip}\n")
                f.write(f"  First seen: {data['first_seen']}\n")
                f.write(f"  Last seen:  {data['last_seen']}\n")
                f.write(f"  Packets:    {data['packet_count']}\n")
                f.write(f"  ICMP ID:    {data['icmp_id']}\n")
                
                if data['payloads']:
                    f.write(f"  Recent payloads:\n")
                    for p in data['payloads'][-3:]:
                        f.write(f"    [{p['time']}] {p['payload'][:80]}\n")
                f.write("\n")
            
            f.write("="*60 + "\n")
            f.write("End of report\n")
        
        print(f"[+] Report exported to {filename}")
    
    def live_monitor(self):
        """Main monitoring loop"""
        print(f"[*] Linked ICMP Scanner - Mode: {self.mode.upper()}")
        print("[*] Monitoring for ICMP reverse shell traffic...")
        print("[*] Press Ctrl+C to stop\n")
        
        packet_count = 0
        
        while self.running:
            try:
                packet, addr = self.sock.recvfrom(65535)
                packet_count += 1
                
                # Parse packet
                packet_info = self.parse_icmp(packet)
                if not packet_info:
                    continue
                
                # Only analyze Echo Request/Reply
                if packet_info["type"] not in [0, 8]:
                    continue
                
                # Check if this looks like shell traffic
                is_shell, indicators = self.is_shell_traffic(packet_info)
                
                if is_shell:
                    # Log the implant
                    self.log_implant(packet_info["src"], packet_info)
                    
                    # Print detection
                    self.print_detection(packet_info, indicators)
                    
                    # Store alert
                    self.alerts.append({
                        "time": time.time(),
                        "src": packet_info["src"],
                        "payload": packet_info["payload"][:200]
                    })
                
                # Show progress every 500 packets
                if packet_count % 500 == 0:
                    print(f"[*] Scanned {packet_count} packets... Active implants: {len(self.detected_implants)}")
                
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                print("\n[-] Stopping scanner...")
                self.running = False
                break
            except Exception as e:
                if self.running:
                    print(f"[-] Error: {e}")
    
    def interactive_command(self):
        """Interactive mode for querying detections"""
        while self.running:
            try:
                print("\n" + "-"*40)
                print("Linked Scanner Commands:")
                print("  list      - Show detected implants")
                print("  report    - Export report to file")
                print("  clear     - Clear alerts")
                print("  quit      - Exit scanner")
                print("-"*40)
                
                cmd = input("\n> ").strip().lower()
                
                if cmd == "list":
                    if not self.detected_implants:
                        print("[*] No implants detected")
                    else:
                        print(f"\nDetected implants ({len(self.detected_implants)}):")
                        for ip, data in self.detected_implants.items():
                            print(f"  • {ip} - {data['packet_count']} packets")
                
                elif cmd == "report":
                    self.export_report()
                
                elif cmd == "clear":
                    self.alerts.clear()
                    print("[+] Alerts cleared")
                
                elif cmd == "quit":
                    self.running = False
                
                else:
                    print("[!] Unknown command")
                    
            except KeyboardInterrupt:
                self.running = False
                break
    
    def run(self):
        """Main execution"""
        if not self.create_socket():
            return
        
        # Start monitor in thread
        monitor_thread = threading.Thread(target=self.live_monitor, daemon=True)
        monitor_thread.start()
        
        # Give monitor time to start
        time.sleep(1)
        
        # Start interactive CLI
        self.interactive_command()
        
        # Print final summary
        print("\n" + "="*50)
        print("FINAL SUMMARY")
        print("="*50)
        if self.detected_implants:
            print(f"[!] Detected {len(self.detected_implants)} ICMP implants:")
            for ip in self.detected_implants:
                print(f"    - {ip}")
        else:
            print("[+] No ICMP shell traffic detected")
        print("="*50)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Linked ICMP Scanner - Detects reverse shell over ICMP")
    parser.add_argument("-m", "--mode", choices=["monitor", "bridge", "stealth"], 
                        default="monitor", help="Operating mode")
    parser.add_argument("-r", "--report", action="store_true", help="Generate report on exit")
    
    args = parser.parse_args()
    
    # Check privileges
    if sys.platform == "win32":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[-] Administrator privileges required!")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("[-] Root privileges required! Use sudo")
            sys.exit(1)
    
    scanner = LinkedICMPScanner(mode=args.mode)
    
    try:
        scanner.run()
    except KeyboardInterrupt:
        pass
    finally:
        if args.report:
            scanner.export_report()
        print("\n[+] Scanner stopped")

if __name__ == "__main__":
    main()