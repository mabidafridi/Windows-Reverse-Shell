#!/usr/bin/env python3
"""
ICMP Packet Scanner - Detects ICMP tunneling / reverse shell traffic
Can be used for blue team defense or to verify your red team tool is working
"""

import socket
import struct
import time
from datetime import datetime
import sys

class ICMPDetector:
    def __init__(self):
        self.sock = None
        self.suspicious_ips = {}  # {ip: {"count": int, "first_seen": time, "payloads": []}}
        self.running = True
        self.threshold = 10  # packets per minute triggers alert
        
    def create_socket(self):
        """Create raw ICMP socket for sniffing"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.sock.settimeout(1)
            print("[+] ICMP sniffer started")
            return True
        except PermissionError:
            print("[-] Root/Admin privileges required for packet sniffing!")
            return False
        except Exception as e:
            print(f"[-] Socket error: {e}")
            return False
    
    def parse_icmp_packet(self, packet, addr):
        """Parse ICMP packet and extract details"""
        try:
            # Parse IP header (20 bytes)
            ip_header = packet[:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            # Get source and destination IPs
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            
            # Check protocol (should be 1 for ICMP)
            protocol = iph[6]
            if protocol != 1:
                return None
            
            # Parse ICMP header (starts after IP header)
            icmp_start = 20
            icmp_header = packet[icmp_start:icmp_start+8]
            icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack('!BBHHH', icmp_header)
            
            # Get payload
            payload = packet[icmp_start+8:].decode('utf-8', errors='ignore').strip('\x00')
            
            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "type": icmp_type,
                "code": icmp_code,
                "id": icmp_id,
                "seq": icmp_seq,
                "payload": payload,
                "size": len(payload)
            }
            
        except Exception as e:
            return None
    
    def analyze_payload(self, payload):
        """Check for suspicious ICMP payload patterns"""
        suspicious_patterns = [
            "HELLO",
            "HEARTBEAT", 
            "READY",
            "cmd.exe",
            "bash",
            "whoami",
            "ls -la",
            "dir",
            "C:\\",
            "/etc/",
            "ping",
            "nc -e",
            "powershell"
        ]
        
        detected = []
        for pattern in suspicious_patterns:
            if pattern.lower() in payload.lower():
                detected.append(pattern)
        
        return detected
    
    def update_stats(self, ip, packet_info):
        """Track suspicious activity per IP"""
        if ip not in self.suspicious_ips:
            self.suspicious_ips[ip] = {
                "count": 0,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "payloads": [],
                "types": set()
            }
        
        stats = self.suspicious_ips[ip]
        stats["count"] += 1
        stats["last_seen"] = time.time()
        stats["types"].add(packet_info["type"])
        
        # Store suspicious payloads (keep last 5)
        if packet_info["payload"] and len(packet_info["payload"]) > 5:
            stats["payloads"].append({
                "time": time.time(),
                "payload": packet_info["payload"][:100],
                "size": packet_info["size"]
            })
            # Keep only last 5
            if len(stats["payloads"]) > 5:
                stats["payloads"].pop(0)
        
        # Check rate
        elapsed = stats["last_seen"] - stats["first_seen"]
        if elapsed > 0:
            rate = stats["count"] / (elapsed / 60)  # packets per minute
            if rate > self.threshold:
                return True  # Alert trigger
        return False
    
    def print_alert(self, ip, packet_info, patterns):
        """Print alert with details"""
        print("\n" + "="*70)
        print(f"[!] ALERT: Suspicious ICMP activity detected!")
        print("="*70)
        print(f"    Source IP:    {ip}")
        print(f"    Destination:  {packet_info['dst_ip']}")
        print(f"    ICMP Type:    {packet_info['type']} (Echo Request=8, Reply=0)")
        print(f"    Packet Size:  {packet_info['size']} bytes")
        print(f"    Detected:     {', '.join(patterns)}")
        
        if packet_info['payload']:
            print(f"    Payload:      {packet_info['payload'][:150]}")
        
        stats = self.suspicious_ips[ip]
        print(f"    Rate:         {stats['count']} packets in {(stats['last_seen'] - stats['first_seen']):.1f} seconds")
        print("="*70 + "\n")
    
    def print_live_packet(self, packet_info):
        """Print normal packet info (for verbose mode)"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        type_name = "ECHO_REQ" if packet_info["type"] == 8 else "ECHO_REPLY" if packet_info["type"] == 0 else f"TYPE_{packet_info['type']}"
        
        # Show payload preview if exists
        payload_preview = ""
        if packet_info["payload"] and len(packet_info["payload"]) > 0:
            preview = packet_info["payload"][:50].replace('\n', ' ')
            payload_preview = f" | Payload: {preview}"
        
        print(f"[{timestamp}] {packet_info['src_ip']} -> {packet_info['dst_ip']} | {type_name} | ID:{packet_info['id']} | Size:{packet_info['size']}{payload_preview}")
    
    def sniff(self, verbose=False):
        """Main sniffing loop"""
        print("[*] Monitoring ICMP traffic...")
        print("[*] Press Ctrl+C to stop\n")
        
        packet_count = 0
        
        while self.running:
            try:
                packet, addr = self.sock.recvfrom(65535)
                packet_count += 1
                
                # Parse packet
                packet_info = self.parse_icmp_packet(packet, addr)
                if not packet_info:
                    continue
                
                # Only analyze Echo Request (type 8) and Echo Reply (type 0)
                if packet_info["type"] not in [0, 8]:
                    continue
                
                # Analyze payload for suspicious patterns
                suspicious = self.analyze_payload(packet_info["payload"])
                
                # Update stats and check for alert
                ip = packet_info["src_ip"]
                trigger = self.update_stats(ip, packet_info)
                
                if suspicious:
                    self.print_alert(ip, packet_info, suspicious)
                elif trigger:
                    print(f"[!] Rate alert: {ip} sending {self.suspicious_ips[ip]['count']} packets in short time")
                elif verbose:
                    self.print_live_packet(packet_info)
                
                # Print every 100 packets for feedback
                if packet_count % 100 == 0 and not verbose:
                    print(f"[*] Captured {packet_count} ICMP packets...")
                
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                print("\n[-] Stopping sniffer...")
                self.running = False
                break
            except Exception as e:
                if self.running:
                    print(f"[-] Error: {e}")
    
    def print_summary(self):
        """Print summary of detected suspicious activity"""
        print("\n" + "="*70)
        print("SCAN SUMMARY")
        print("="*70)
        
        if not self.suspicious_ips:
            print("[+] No suspicious ICMP activity detected")
            return
        
        print(f"[!] {len(self.suspicious_ips)} suspicious IPs found:\n")
        
        for ip, stats in self.suspicious_ips.items():
            duration = stats["last_seen"] - stats["first_seen"]
            print(f"  IP: {ip}")
            print(f"      Packets: {stats['count']} over {duration:.1f} seconds")
            print(f"      ICMP Types: {stats['types']}")
            
            if stats['payloads']:
                print(f"      Last payloads:")
                for p in stats['payloads'][-3:]:
                    print(f"        - {p['payload'][:80]}")
            print()
        
        print("="*70)
    
    def run(self, verbose=False):
        """Main execution"""
        if not self.create_socket():
            return
        
        try:
            self.sniff(verbose)
        finally:
            self.print_summary()
            if self.sock:
                self.sock.close()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="ICMP Tunnel Detector - Find reverse shells hiding in ping traffic")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all ICMP packets")
    parser.add_argument("-t", "--threshold", type=int, default=10, help="Packets per minute threshold (default: 10)")
    
    args = parser.parse_args()
    
    if sys.platform == "win32":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[-] Administrator privileges required on Windows!")
            print("    Right-click -> Run as Administrator")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("[-] Root privileges required on Linux!")
            print("    Run with: sudo python3 packet_scanner.py")
            sys.exit(1)
    
    detector = ICMPDetector()
    detector.threshold = args.threshold
    detector.run(verbose=args.verbose)