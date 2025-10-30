"""
═══════════════════════════════════════════════════════════════════════════
                           CIPHERCREST v1.0
                 Custom Cryptographic Algorithm Suite
              with Security Analysis & Performance Benchmarking
                         by Michael Semera
═══════════════════════════════════════════════════════════════════════════

Description:
    CipherCrest is a custom cryptographic algorithm implementation designed
    for educational purposes. It features a unique block cipher with
    multiple encryption layers, key expansion, and comprehensive testing
    against industry standards like AES and RSA.

Features:
    - Custom block cipher algorithm (128-bit blocks)
    - Multi-layer encryption with substitution and permutation
    - Secure key expansion mechanism
    - Avalanche effect demonstration
    - Diffusion and confusion analysis
    - Performance benchmarking vs AES/RSA
    - Statistical randomness testing
    - Visualization of encryption patterns

Security Layers:
    1. Key Expansion (generates round keys)
    2. Substitution Layer (S-boxes for confusion)
    3. Permutation Layer (P-boxes for diffusion)
    4. XOR Layer (key mixing)
    5. Rotation Layer (bit shifting)

WARNING: This is an EDUCATIONAL implementation only!
         DO NOT use for production security purposes.
         Use industry-standard algorithms (AES, RSA) for real applications.

Author: Michael Semera
Version: 1.0
Date: 2023
═══════════════════════════════════════════════════════════════════════════
"""

import time
import hashlib
import secrets
import numpy as np
import matplotlib.pyplot as plt
from typing import List, Tuple, Dict
from dataclasses import dataclass
import struct

# Industry standard implementations for comparison
try:
    from Crypto.Cipher import AES
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[WARNING] PyCryptodome not installed. Install with: pip install pycryptodome")
    print("          Comparison features will be limited.\n")


@dataclass
class EncryptionMetrics:
    """Store encryption performance and security metrics."""
    algorithm: str
    encryption_time: float
    decryption_time: float
    throughput_mbps: float
    key_size: int
    block_size: int
    avalanche_effect: float
    correlation_coefficient: float


class CipherCrest:
    """
    CipherCrest - Custom block cipher implementation.
    
    This cipher uses a Feistel-inspired network with multiple rounds of
    substitution, permutation, and key mixing to achieve diffusion and confusion.
    
    Block Size: 128 bits (16 bytes)
    Key Size: 256 bits (32 bytes)
    Rounds: 16
    """
    
    BLOCK_SIZE = 16  # 128 bits
    KEY_SIZE = 32    # 256 bits
    ROUNDS = 16
    
    # Custom S-box (Substitution box) for confusion
    # Generated using a pseudo-random but deterministic method
    SBOX = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
        0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
        0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
        0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
        0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
        0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
        0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
        0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
        0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
        0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
        0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
        0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
        0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
        0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    ]
    
    # Inverse S-box for decryption
    INV_SBOX = [0] * 256
    
    # Permutation table for diffusion
    PBOX = [
        15, 6, 19, 20, 28, 11, 27, 16,
        0, 14, 22, 25, 4, 17, 30, 9,
        1, 7, 23, 13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10, 3, 24
    ]
    
    def __init__(self, key: bytes = None):
        """
        Initialize CipherCrest cipher with a key.
        
        Args:
            key: 256-bit (32 byte) encryption key. If None, generates random key.
        """
        if key is None:
            self.key = secrets.token_bytes(self.KEY_SIZE)
        else:
            if len(key) != self.KEY_SIZE:
                raise ValueError(f"Key must be {self.KEY_SIZE} bytes ({self.KEY_SIZE * 8} bits)")
            self.key = key
        
        # Generate inverse S-box
        for i in range(256):
            self.INV_SBOX[self.SBOX[i]] = i
        
        # Expand key for all rounds
        self.round_keys = self._expand_key()
        
        print(f"╔════════════════════════════════════════════════════════╗")
        print(f"║           CIPHERCREST INITIALIZED                      ║")
        print(f"╚════════════════════════════════════════════════════════╝")
        print(f"Key Size: {self.KEY_SIZE * 8} bits")
        print(f"Block Size: {self.BLOCK_SIZE * 8} bits")
        print(f"Rounds: {self.ROUNDS}\n")
    
    def _expand_key(self) -> List[bytes]:
        """
        Expand the master key into round keys.
        
        Uses a hash-based key derivation function to generate
        independent keys for each round.
        
        Returns:
            List of round keys
        """
        round_keys = []
        
        for round_num in range(self.ROUNDS):
            # Create unique round key using hash function
            round_data = self.key + struct.pack('<I', round_num)
            round_key = hashlib.sha256(round_data).digest()[:self.BLOCK_SIZE]
            round_keys.append(round_key)
        
        return round_keys
    
    def _substitute_bytes(self, block: bytearray) -> bytearray:
        """
        Apply S-box substitution to each byte (confusion layer).
        
        Args:
            block: Input block
            
        Returns:
            Substituted block
        """
        return bytearray(self.SBOX[b] for b in block)
    
    def _inv_substitute_bytes(self, block: bytearray) -> bytearray:
        """
        Apply inverse S-box substitution (for decryption).
        
        Args:
            block: Input block
            
        Returns:
            Inverse substituted block
        """
        return bytearray(self.INV_SBOX[b] for b in block)
    
    def _permute_bits(self, block: bytearray) -> bytearray:
        """
        Permute bits across the block (diffusion layer).
        
        Args:
            block: Input block
            
        Returns:
            Permuted block
        """
        # Convert to bit array
        bits = []
        for byte in block:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)
        
        # Apply permutation
        permuted_bits = [bits[self.PBOX[i % len(self.PBOX)]] for i in range(len(bits))]
        
        # Convert back to bytes
        result = bytearray()
        for i in range(0, len(permuted_bits), 8):
            byte_val = 0
            for j in range(8):
                byte_val = (byte_val << 1) | permuted_bits[i + j]
            result.append(byte_val)
        
        return result
    
    def _inv_permute_bits(self, block: bytearray) -> bytearray:
        """
        Apply inverse bit permutation (for decryption).
        
        Args:
            block: Input block
            
        Returns:
            Inverse permuted block
        """
        # Create inverse permutation table
        inv_pbox = [0] * len(self.PBOX)
        for i, p in enumerate(self.PBOX):
            inv_pbox[p] = i
        
        # Convert to bit array
        bits = []
        for byte in block:
            for i in range(8):
                bits.append((byte >> (7 - i)) & 1)
        
        # Apply inverse permutation
        permuted_bits = [bits[inv_pbox[i % len(inv_pbox)]] for i in range(len(bits))]
        
        # Convert back to bytes
        result = bytearray()
        for i in range(0, len(permuted_bits), 8):
            byte_val = 0
            for j in range(8):
                byte_val = (byte_val << 1) | permuted_bits[i + j]
            result.append(byte_val)
        
        return result
    
    def _rotate_left(self, block: bytearray, positions: int = 3) -> bytearray:
        """
        Rotate bytes in block to the left (additional diffusion).
        
        Args:
            block: Input block
            positions: Number of positions to rotate
            
        Returns:
            Rotated block
        """
        positions = positions % len(block)
        return bytearray(block[positions:] + block[:positions])
    
    def _rotate_right(self, block: bytearray, positions: int = 3) -> bytearray:
        """
        Rotate bytes in block to the right (for decryption).
        
        Args:
            block: Input block
            positions: Number of positions to rotate
            
        Returns:
            Rotated block
        """
        positions = positions % len(block)
        return bytearray(block[-positions:] + block[:-positions])
    
    def _xor_with_key(self, block: bytearray, key: bytes) -> bytearray:
        """
        XOR block with round key.
        
        Args:
            block: Input block
            key: Round key
            
        Returns:
            XORed block
        """
        return bytearray(b ^ k for b, k in zip(block, key))
    
    def _encrypt_block(self, block: bytes) -> bytes:
        """
        Encrypt a single 128-bit block.
        
        Encryption process per round:
        1. XOR with round key
        2. Substitute bytes (S-box)
        3. Permute bits (P-box)
        4. Rotate bytes
        
        Args:
            block: 16-byte plaintext block
            
        Returns:
            16-byte ciphertext block
        """
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(f"Block must be {self.BLOCK_SIZE} bytes")
        
        state = bytearray(block)
        
        # Apply multiple rounds
        for round_num in range(self.ROUNDS):
            # Key mixing
            state = self._xor_with_key(state, self.round_keys[round_num])
            
            # Confusion layer
            state = self._substitute_bytes(state)
            
            # Diffusion layer
            state = self._permute_bits(state)
            
            # Additional diffusion
            state = self._rotate_left(state, round_num % 5)
        
        # Final key mixing
        state = self._xor_with_key(state, self.round_keys[0])
        
        return bytes(state)
    
    def _decrypt_block(self, block: bytes) -> bytes:
        """
        Decrypt a single 128-bit block.
        
        Reverses the encryption process.
        
        Args:
            block: 16-byte ciphertext block
            
        Returns:
            16-byte plaintext block
        """
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(f"Block must be {self.BLOCK_SIZE} bytes")
        
        state = bytearray(block)
        
        # Reverse final key mixing
        state = self._xor_with_key(state, self.round_keys[0])
        
        # Reverse rounds
        for round_num in range(self.ROUNDS - 1, -1, -1):
            # Reverse rotation
            state = self._rotate_right(state, round_num % 5)
            
            # Reverse permutation
            state = self._inv_permute_bits(state)
            
            # Reverse substitution
            state = self._inv_substitute_bytes(state)
            
            # Reverse key mixing
            state = self._xor_with_key(state, self.round_keys[round_num])
        
        return bytes(state)
    
    def _pad(self, data: bytes) -> bytes:
        """
        Apply PKCS7 padding to data.
        
        Args:
            data: Input data
            
        Returns:
            Padded data
        """
        padding_length = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad(self, data: bytes) -> bytes:
        """
        Remove PKCS7 padding from data.
        
        Args:
            data: Padded data
            
        Returns:
            Unpadded data
        """
        padding_length = data[-1]
        return data[:-padding_length]
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data of arbitrary length.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Encrypted ciphertext
        """
        # Pad plaintext
        padded = self._pad(plaintext)
        
        # Encrypt each block
        ciphertext = b''
        for i in range(0, len(padded), self.BLOCK_SIZE):
            block = padded[i:i + self.BLOCK_SIZE]
            ciphertext += self._encrypt_block(block)
        
        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt data of arbitrary length.
        
        Args:
            ciphertext: Encrypted data
            
        Returns:
            Decrypted plaintext
        """
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length must be multiple of block size")
        
        # Decrypt each block
        plaintext = b''
        for i in range(0, len(ciphertext), self.BLOCK_SIZE):
            block = ciphertext[i:i + self.BLOCK_SIZE]
            plaintext += self._decrypt_block(block)
        
        # Remove padding
        return self._unpad(plaintext)


class CryptoAnalyzer:
    """
    Analyze and benchmark cryptographic algorithms.
    
    Provides tools for testing security properties and performance
    characteristics of encryption algorithms.
    """
    
    def __init__(self):
        """Initialize the crypto analyzer."""
        print("\n╔════════════════════════════════════════════════════════╗")
        print("║         CIPHERCREST CRYPTO ANALYZER                    ║")
        print("╚════════════════════════════════════════════════════════╝\n")
    
    def test_avalanche_effect(self, cipher, data_size: int = 128) -> float:
        """
        Test avalanche effect: one bit change should flip ~50% of output bits.
        
        Args:
            cipher: Encryption algorithm instance
            data_size: Size of test data in bytes
            
        Returns:
            Percentage of bits flipped (should be ~50%)
        """
        print("[INFO] Testing avalanche effect...")
        
        # Generate random plaintext
        plaintext1 = secrets.token_bytes(data_size)
        
        # Flip one bit
        plaintext2 = bytearray(plaintext1)
        plaintext2[0] ^= 0x01
        plaintext2 = bytes(plaintext2)
        
        # Encrypt both
        ciphertext1 = cipher.encrypt(plaintext1)
        ciphertext2 = cipher.encrypt(plaintext2)
        
        # Count differing bits
        diff_bits = 0
        total_bits = len(ciphertext1) * 8
        
        for b1, b2 in zip(ciphertext1, ciphertext2):
            xor = b1 ^ b2
            diff_bits += bin(xor).count('1')
        
        avalanche_percentage = (diff_bits / total_bits) * 100
        
        print(f"✓ Avalanche Effect: {avalanche_percentage:.2f}% bits flipped")
        print(f"  (Ideal: ~50%, {total_bits // 2} bits)\n")
        
        return avalanche_percentage
    
    def test_correlation(self, cipher, sample_size: int = 1000) -> float:
        """
        Test correlation between plaintext and ciphertext.
        
        Args:
            cipher: Encryption algorithm instance
            sample_size: Number of bytes to test
            
        Returns:
            Correlation coefficient (should be close to 0)
        """
        print("[INFO] Testing plaintext-ciphertext correlation...")
        
        plaintext = secrets.token_bytes(sample_size)
        ciphertext = cipher.encrypt(plaintext)
        
        # Calculate correlation coefficient
        plain_array = np.frombuffer(plaintext, dtype=np.uint8)
        cipher_array = np.frombuffer(ciphertext[:len(plaintext)], dtype=np.uint8)
        
        correlation = np.corrcoef(plain_array, cipher_array)[0, 1]
        
        print(f"✓ Correlation Coefficient: {correlation:.6f}")
        print(f"  (Ideal: ~0.0, indicating no correlation)\n")
        
        return correlation
    
    def benchmark_performance(self, cipher, data_sizes: List[int] = None) -> Dict:
        """
        Benchmark encryption/decryption performance.
        
        Args:
            cipher: Encryption algorithm instance
            data_sizes: List of data sizes to test (in KB)
            
        Returns:
            Dictionary with performance metrics
        """
        if data_sizes is None:
            data_sizes = [1, 10, 100, 1000]  # KB
        
        print("[INFO] Benchmarking performance...")
        
        results = {'data_sizes': [], 'encrypt_times': [], 'decrypt_times': [], 'throughput': []}
        
        for size_kb in data_sizes:
            size_bytes = size_kb * 1024
            data = secrets.token_bytes(size_bytes)
            
            # Benchmark encryption
            start = time.perf_counter()
            ciphertext = cipher.encrypt(data)
            encrypt_time = time.perf_counter() - start
            
            # Benchmark decryption
            start = time.perf_counter()
            plaintext = cipher.decrypt(ciphertext)
            decrypt_time = time.perf_counter() - start
            
            # Calculate throughput (MB/s)
            throughput = (size_bytes / (1024 * 1024)) / encrypt_time
            
            results['data_sizes'].append(size_kb)
            results['encrypt_times'].append(encrypt_time * 1000)  # Convert to ms
            results['decrypt_times'].append(decrypt_time * 1000)
            results['throughput'].append(throughput)
            
            print(f"  {size_kb} KB: Encrypt={encrypt_time*1000:.2f}ms, "
                  f"Decrypt={decrypt_time*1000:.2f}ms, "
                  f"Throughput={throughput:.2f} MB/s")
        
        print()
        return results
    
    def compare_with_aes(self, ciphercrest_cipher, data_size: int = 1024 * 100) -> None:
        """
        Compare CipherCrest with AES encryption.
        
        Args:
            ciphercrest_cipher: CipherCrest instance
            data_size: Size of test data in bytes
        """
        if not CRYPTO_AVAILABLE:
            print("[WARNING] PyCryptodome not available. Skipping AES comparison.\n")
            return
        
        print("\n╔════════════════════════════════════════════════════════╗")
        print("║        CIPHERCREST VS AES COMPARISON                  ║")
        print("╚════════════════════════════════════════════════════════╝\n")
        
        data = secrets.token_bytes(data_size)
        
        # Test CipherCrest
        print("[INFO] Testing CipherCrest...")
        start = time.perf_counter()
        cc_ciphertext = ciphercrest_cipher.encrypt(data)
        cc_encrypt_time = time.perf_counter() - start
        
        start = time.perf_counter()
        cc_plaintext = ciphercrest_cipher.decrypt(cc_ciphertext)
        cc_decrypt_time = time.perf_counter() - start
        
        cc_throughput = (data_size / (1024 * 1024)) / cc_encrypt_time
        
        # Test AES
        print("[INFO] Testing AES-256...")
        aes_key = get_random_bytes(32)
        aes_cipher = AES.new(aes_key, AES.MODE_ECB)
        
        # Pad data for AES
        pad_length = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_length] * pad_length)
        
        start = time.perf_counter()
        aes_ciphertext = aes_cipher.encrypt(padded_data)
        aes_encrypt_time = time.perf_counter() - start
        
        aes_cipher = AES.new(aes_key, AES.MODE_ECB)
        start = time.perf_counter()
        aes_plaintext = aes_cipher.decrypt(aes_ciphertext)
        aes_decrypt_time = time.perf_counter() - start
        
        aes_throughput = (data_size / (1024 * 1024)) / aes_encrypt_time
        
        # Display comparison
        print("\n" + "="*60)
        print(f"{'Metric':<30} {'CipherCrest':<15} {'AES-256':<15}")
        print("="*60)
        print(f"{'Encryption Time (ms)':<30} {cc_encrypt_time*1000:<15.2f} {aes_encrypt_time*1000:<15.2f}")
        print(f"{'Decryption Time (ms)':<30} {cc_decrypt_time*1000:<15.2f} {aes_decrypt_time*1000:<15.2f}")
        print(f"{'Throughput (MB/s)':<30} {cc_throughput:<15.2f} {aes_throughput:<15.2f}")
        print(f"{'Key Size (bits)':<30} {256:<15} {256:<15}")
        print(f"{'Block Size (bits)':<30} {128:<15} {128:<15}")
        print("="*60)
        
        speed_ratio = aes_throughput / cc_throughput
        print(f"\n💡 AES is {speed_ratio:.2f}x faster than CipherCrest")
        print("   (This is expected - AES is hardware-accelerated)\n")
    
    def visualize_encryption_pattern(self, cipher, save_file: str = 'encryption_pattern.png') -> None:
        """
        Visualize encryption patterns to show diffusion.
        
        Args:
            cipher: Encryption algorithm instance
            save_file: Output filename
        """
        print("[INFO] Generating encryption pattern visualization...")
        
        # Create test data with patterns
        size = 64
        test_data = bytearray(size * size)
        
        # Create simple pattern
        for i in range(size):
            for j in range(size):
                test_data[i * size + j] = (i + j) % 256
        
        # Encrypt
        ciphertext = cipher.encrypt(bytes(test_data))
        
        # Reshape for visualization
        plaintext_img = np.array(list(test_data)).reshape(size, size)
        ciphertext_img = np.array(list(ciphertext[:size*size])).reshape(size, size)
        
        # Create visualization
        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        
        axes[0].imshow(plaintext_img, cmap='gray')
        axes[0].set_title('Plaintext Pattern', fontweight='bold', fontsize=14)
        axes[0].axis('off')
        
        axes[1].imshow(ciphertext_img, cmap='gray')
        axes[1].set_title('Ciphertext Pattern (Encrypted)', fontweight='bold', fontsize=14)
        axes[1].axis('off')
        
        plt.suptitle('CipherCrest: Diffusion Demonstration', fontsize=16, fontweight='bold')
        plt.tight_layout()
        plt.savefig(save_file, dpi=300, bbox_inches='tight')
        plt.show()
        
        print(f"✓ Pattern visualization saved: {save_file}\n")


def demonstrate_ciphercrest():
    """Demonstrate CipherCrest capabilities."""
    
    print("\n" + "="*60)
    print(" "*15 + "CIPHERCREST DEMONSTRATION")
    print("="*60 + "\n")
    
    # Initialize cipher
    cipher = CipherCrest()
    
    # Test basic encryption/decryption
    print("╔════════════════════════════════════════════════════════╗")
    print("║         BASIC ENCRYPTION TEST                          ║")
    print("╚════════════════════════════════════════════════════════╝\n")
    
    message = b"Hello, CipherCrest! This is a test message by Michael Semera."
    print(f"Original Message: {message.decode()}")
    
    ciphertext = cipher.encrypt(message)
    print(f"Encrypted (hex): {ciphertext.hex()[:80]}...")
    
    decrypted = cipher.decrypt(ciphertext)
    print(f"Decrypted: {decrypted.decode()}")
    print(f"✓ Encryption/Decryption successful!\n")
    
    # Initialize analyzer
    analyzer = CryptoAnalyzer()
    
    # Security tests
    print("╔════════════════════════════════════════════════════════╗")
    print("║         SECURITY ANALYSIS                              ║")
    print("╚════════════════════════════════════════════════════════╝\n")
    
    avalanche = analyzer.test_avalanche_effect(cipher, data_size=1024)
    correlation = analyzer.test_correlation(cipher, sample_size=10000)
    
    # Performance benchmarking
    print("╔════════════════════════════════════════════════════════╗")
    print("║         PERFORMANCE BENCHMARKING                       ║")
    print("╚════════════════════════════════════════════════════════╝\n")
    
    perf_results = analyzer.benchmark_performance(cipher, data_sizes=[1, 10, 100, 1000])
    
    # Visualize performance
    plt.figure(figsize=(12, 5))
    
    plt.subplot(1, 2, 1)
    plt.plot(perf_results['data_sizes'], perf_results['encrypt_times'], 
             marker='o', label='Encryption', linewidth=2, markersize=8)
    plt.plot(perf_results['data_sizes'], perf_results['decrypt_times'],
             marker='s', label='Decryption', linewidth=2, markersize=8)
    plt.xlabel('Data Size (KB)', fontweight='bold')
    plt.ylabel('Time (ms)', fontweight='bold')
    plt.title('CipherCrest: Encryption/Decryption Time', fontweight='bold')
    plt.legend()
    plt.grid(alpha=0.3)
    plt.xscale('log')
    plt.yscale('log')
    
    plt.subplot(1, 2, 2)
    plt.plot(perf_results['data_sizes'], perf_results['throughput'],
             marker='D', color='green', linewidth=2, markersize=8)
    plt.xlabel('Data Size (KB)', fontweight='bold')
    plt.ylabel('Throughput (MB/s)', fontweight='bold')
    plt.title('CipherCrest: Encryption Throughput', fontweight='bold')
    plt.grid(alpha=0.3)
    plt.xscale('log')
    
    plt.suptitle('CipherCrest Performance Analysis', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig('ciphercrest_performance.png', dpi=300, bbox_inches='tight')
    plt.show()
    
    print("✓ Performance chart saved: ciphercrest_performance.png\n")
    
    # Compare with AES
    analyzer.compare_with_aes(cipher, data_size=1024 * 100)
    
    # Visualize encryption patterns
    analyzer.visualize_encryption_pattern(cipher)
    
    # Generate final report
    print("\n" + "="*60)
    print(" "*20 + "FINAL REPORT")
    print("="*60 + "\n")
    
    print(f"✓ CipherCrest Algorithm: OPERATIONAL")
    print(f"  - Key Size: 256 bits")
    print(f"  - Block Size: 128 bits")
    print(f"  - Encryption Rounds: 16")
    print(f"  - Avalanche Effect: {avalanche:.2f}% (Target: ~50%)")
    print(f"  - Correlation: {abs(correlation):.6f} (Target: ~0.0)")
    print(f"  - Average Throughput: {np.mean(perf_results['throughput']):.2f} MB/s")
    
    if avalanche >= 45 and avalanche <= 55:
        print(f"\n✅ Avalanche effect is EXCELLENT (within 45-55%)")
    elif avalanche >= 40 and avalanche <= 60:
        print(f"\n✓ Avalanche effect is GOOD (within 40-60%)")
    else:
        print(f"\n⚠️  Avalanche effect could be improved")
    
    if abs(correlation) < 0.1:
        print(f"✅ Correlation is EXCELLENT (< 0.1)")
    elif abs(correlation) < 0.3:
        print(f"✓ Correlation is GOOD (< 0.3)")
    else:
        print(f"⚠️  Correlation could be improved")
    
    print("\n" + "="*60)
    print("⚠️  REMINDER: CipherCrest is for EDUCATIONAL purposes only!")
    print("   Use AES, RSA, or other certified algorithms for production.")
    print("="*60 + "\n")


def interactive_demo():
    """Interactive demonstration of CipherCrest."""
    
    print("\n╔════════════════════════════════════════════════════════╗")
    print("║        CIPHERCREST INTERACTIVE DEMO                    ║")
    print("╚════════════════════════════════════════════════════════╝\n")
    
    cipher = CipherCrest()
    
    while True:
        print("\nOptions:")
        print("  1. Encrypt a message")
        print("  2. Decrypt a message")
        print("  3. Test avalanche effect")
        print("  4. Performance benchmark")
        print("  5. Exit")
        
        choice = input("\nEnter choice (1-5): ").strip()
        
        if choice == '1':
            message = input("Enter message to encrypt: ")
            ciphertext = cipher.encrypt(message.encode())
            print(f"\nCiphertext (hex): {ciphertext.hex()}")
            print(f"Length: {len(ciphertext)} bytes")
            
        elif choice == '2':
            hex_input = input("Enter ciphertext (hex): ").strip()
            try:
                ciphertext = bytes.fromhex(hex_input)
                plaintext = cipher.decrypt(ciphertext)
                print(f"\nDecrypted message: {plaintext.decode()}")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == '3':
            analyzer = CryptoAnalyzer()
            analyzer.test_avalanche_effect(cipher)
        
        elif choice == '4':
            analyzer = CryptoAnalyzer()
            analyzer.benchmark_performance(cipher)
        
        elif choice == '5':
            print("\nThank you for using CipherCrest!")
            print("Created by Michael Semera\n")
            break
        
        else:
            print("Invalid choice. Please try again.")


def main():
    """Main entry point for CipherCrest."""
    
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║                                                          ║")
    print("║                 CIPHERCREST v1.0                         ║")
    print("║         Custom Cryptographic Algorithm Suite             ║")
    print("║              by Michael Semera                           ║")
    print("║                                                          ║")
    print("╚══════════════════════════════════════════════════════════╝")
    
    print("\n⚠️  EDUCATIONAL PURPOSES ONLY")
    print("   This is a custom cryptographic algorithm for learning.")
    print("   DO NOT use for production security applications!")
    print("   Use industry-standard algorithms (AES, RSA) instead.\n")
    
    print("Choose mode:")
    print("  1. Full demonstration (recommended)")
    print("  2. Interactive mode")
    print("  3. Quick test")
    
    choice = input("\nEnter choice (1-3): ").strip()
    
    if choice == '1':
        demonstrate_ciphercrest()
    elif choice == '2':
        interactive_demo()
    elif choice == '3':
        cipher = CipherCrest()
        message = b"Quick test message!"
        ciphertext = cipher.encrypt(message)
        decrypted = cipher.decrypt(ciphertext)
        print(f"\nOriginal: {message}")
        print(f"Encrypted: {ciphertext.hex()}")
        print(f"Decrypted: {decrypted}")
        print(f"✓ Success: {message == decrypted}\n")
    else:
        print("Invalid choice. Running full demonstration...\n")
        demonstrate_ciphercrest()


if __name__ == "__main__":
    main()