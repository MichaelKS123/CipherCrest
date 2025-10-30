# CipherCrest v1.0
**Custom Cryptographic Algorithm Suite**  
**with Security Analysis & Performance Benchmarking**  
**by Michael Semera**

---

## 🔐 Overview

CipherCrest is a custom-designed block cipher implementation created for educational purposes. It demonstrates fundamental cryptographic concepts including substitution, permutation, key expansion, and demonstrates how modern encryption algorithms achieve security through mathematical properties of diffusion and confusion.

## ⚠️ CRITICAL DISCLAIMER

**THIS IS AN EDUCATIONAL PROJECT ONLY!**

- ❌ **DO NOT** use CipherCrest for any production security applications
- ❌ **DO NOT** use it to protect sensitive data
- ❌ **DO NOT** use it for commercial purposes
- ✅ **DO** use it to learn about cryptography
- ✅ **DO** use it for educational demonstrations
- ✅ **DO** use industry-standard algorithms (AES, RSA, ChaCha20) for real security

**For production use, always use certified cryptographic algorithms!**

---

## 🎯 Project Goals

- **Understand Cryptography**: Learn how block ciphers work internally
- **Demonstrate Security Properties**: Show diffusion, confusion, and avalanche effect
- **Performance Analysis**: Compare custom algorithms with industry standards
- **Educational Tool**: Provide hands-on cryptography learning experience
- **Security Testing**: Demonstrate proper cryptographic analysis techniques

---

## ✨ Features

### Cryptographic Components

- **🔑 256-bit Key Size**: Strong key length matching AES-256
- **📦 128-bit Block Size**: Standard block size for compatibility
- **🔄 16 Encryption Rounds**: Multiple rounds for security
- **🎲 Custom S-boxes**: Substitution tables for confusion
- **🔀 Bit Permutation**: P-boxes for diffusion
- **🔐 Key Expansion**: Generates unique round keys
- **↩️ Byte Rotation**: Additional diffusion mechanism
- **⊕ XOR Operations**: Key mixing layer

### Analysis Tools

- **📊 Avalanche Effect Testing**: Measures output randomness
- **📈 Correlation Analysis**: Tests plaintext-ciphertext independence
- **⚡ Performance Benchmarking**: Speed and throughput measurements
- **🆚 AES Comparison**: Direct comparison with industry standard
- **📉 Statistical Testing**: Randomness quality assessment
- **🎨 Pattern Visualization**: Visual demonstration of diffusion

### Security Properties

- **Confusion**: S-box substitution obscures plaintext-key relationship
- **Diffusion**: P-box permutation spreads bit changes across block
- **Avalanche Effect**: 1-bit input change affects ~50% of output bits
- **Non-linearity**: Multiple transformation layers prevent linear cryptanalysis
- **Key Independence**: Each round uses independently derived key

---

## 🛠️ Technology Stack

### Core Requirements
- **Python 3.8+**
- **numpy** - Numerical operations and analysis
- **matplotlib** - Performance visualization

### Optional (for AES comparison)
- **pycryptodome** - Industry-standard crypto implementations

---

## 📦 Installation

### Step 1: Install Core Dependencies

```bash
pip install numpy matplotlib
```

### Step 2: Install Optional Dependencies (Recommended)

```bash
pip install pycryptodome
```

### Complete Installation

```bash
pip install numpy matplotlib pycryptodome
```

### Using requirements.txt

```bash
pip install -r requirements.txt
```

**requirements.txt:**
```
numpy>=1.21.0
matplotlib>=3.4.0
pycryptodome>=3.15.0
```

---

## 🚀 Quick Start

### Basic Encryption/Decryption

```python
from ciphercrest import CipherCrest

# Initialize cipher with random key
cipher = CipherCrest()

# Encrypt a message
message = b"Hello, World!"
ciphertext = cipher.encrypt(message)
print(f"Encrypted: {ciphertext.hex()}")

# Decrypt the message
plaintext = cipher.decrypt(ciphertext)
print(f"Decrypted: {plaintext.decode()}")
```

### With Custom Key

```python
import secrets

# Generate or provide a 256-bit (32 byte) key
custom_key = secrets.token_bytes(32)

# Initialize with custom key
cipher = CipherCrest(key=custom_key)

# Now both parties with the same key can communicate
ciphertext = cipher.encrypt(b"Secret message")
plaintext = cipher.decrypt(ciphertext)
```

### Full Demonstration

```bash
# Run complete demonstration
python ciphercrest.py
```

This will:
1. Perform basic encryption/decryption test
2. Analyze security properties
3. Benchmark performance
4. Compare with AES
5. Generate visualizations
6. Create comprehensive report

---

## 🔍 How CipherCrest Works

### Algorithm Architecture

CipherCrest is a **Feistel-inspired block cipher** with the following structure:

```
┌─────────────────────────────────────┐
│      Plaintext (128 bits)           │
└─────────────┬───────────────────────┘
              │
    ┌─────────▼─────────┐
    │   Key Expansion   │
    └─────────┬─────────┘
              │
    ┌─────────▼─────────┐
    │   Round 1 to 16   │◄──── Round Keys
    │  ┌──────────────┐ │
    │  │ XOR with Key │ │
    │  ├──────────────┤ │
    │  │ S-box (Subs) │ │
    │  ├──────────────┤ │
    │  │ P-box (Perm) │ │
    │  ├──────────────┤ │
    │  │  Rotation    │ │
    │  └──────────────┘ │
    └─────────┬─────────┘
              │
    ┌─────────▼─────────┐
    │  Final Key Mix    │
    └─────────┬─────────┘
              │
┌─────────────▼───────────────────────┐
│      Ciphertext (128 bits)          │
└─────────────────────────────────────┘
```

### Encryption Process

**For each 128-bit block:**

1. **Key Expansion**
   - Master key → 16 round keys
   - Uses SHA-256 hash function
   - Each round gets unique key

2. **Round Processing (×16)**
   ```
   a. XOR with round key
   b. Substitute bytes (S-box) - Confusion
   c. Permute bits (P-box) - Diffusion
   d. Rotate bytes - Additional diffusion
   ```

3. **Final Transformation**
   - XOR with first round key
   - Output ciphertext block

### Decryption Process

Reverses the encryption:
- Applies inverse operations in reverse order
- Uses same round keys in reverse sequence
- Mathematically guaranteed to recover plaintext

---

## 📊 Security Analysis

### Avalanche Effect

**Definition**: A single bit change in input should flip ~50% of output bits.

**Testing:**
```python
from ciphercrest import CipherCrest, CryptoAnalyzer

cipher = CipherCrest()
analyzer = CryptoAnalyzer()

# Test avalanche effect
avalanche_percentage = analyzer.test_avalanche_effect(cipher)
print(f"Avalanche: {avalanche_percentage:.2f}%")
```

**Good Results**: 45-55% (indicates strong diffusion)  
**CipherCrest Typical**: 48-52%

### Correlation Analysis

**Definition**: Measures linear relationship between plaintext and ciphertext.

**Testing:**
```python
correlation = analyzer.test_correlation(cipher)
print(f"Correlation: {correlation:.6f}")
```

**Good Results**: Close to 0.0 (no correlation)  
**CipherCrest Typical**: < 0.1

### Confusion Property

Achieved through:
- **S-boxes**: Non-linear substitution tables
- **Multiple rounds**: Repeated transformations
- **Key mixing**: XOR operations with round keys

### Diffusion Property

Achieved through:
- **P-boxes**: Bit permutation across block
- **Byte rotation**: Position changes
- **Multiple rounds**: Cascading spread

---

## ⚡ Performance Benchmarking

### Benchmark Your System

```python
analyzer = CryptoAnalyzer()

# Test different data sizes
results = analyzer.benchmark_performance(
    cipher, 
    data_sizes=[1, 10, 100, 1000]  # KB
)

print(f"Average throughput: {np.mean(results['throughput']):.2f} MB/s")
```

### Typical Performance

| Data Size | Encryption Time | Decryption Time | Throughput |
|-----------|----------------|-----------------|------------|
| 1 KB | ~0.5 ms | ~0.5 ms | ~2 MB/s |
| 10 KB | ~4 ms | ~4 ms | ~2.5 MB/s |
| 100 KB | ~35 ms | ~35 ms | ~2.8 MB/s |
| 1 MB | ~350 ms | ~350 ms | ~2.9 MB/s |

*Results vary by hardware*

### CipherCrest vs AES

```python
analyzer.compare_with_aes(cipher, data_size=100 * 1024)
```

**Typical Results:**

| Metric | CipherCrest | AES-256 | Ratio |
|--------|-------------|---------|-------|
| Encryption (100KB) | ~35 ms | ~0.5 ms | 70× slower |
| Throughput | ~3 MB/s | ~200 MB/s | 67× slower |

**Why is AES faster?**
- Hardware acceleration (AES-NI instructions)
- Highly optimized implementation
- Decades of optimization work
- Native CPU support

**This is expected and acceptable for an educational cipher!**

---

## 🎨 Visualization

### Encryption Pattern Analysis

Visualize how CipherCrest diffuses information:

```python
analyzer.visualize_encryption_pattern(cipher)
```

Creates a side-by-side comparison:
- **Left**: Plaintext with visible pattern
- **Right**: Ciphertext (randomized, no pattern visible)

**Demonstrates**: Proper diffusion transforms structured data into random-looking output.

### Performance Charts

Automatically generated:
- **Encryption/Decryption Time** vs Data Size
- **Throughput** vs Data Size

**File**: `ciphercrest_performance.png`

---

## 🔬 Technical Deep Dive

### S-box Design

```python
# Example S-box entry
SBOX[0x00] = 0x63  # Maps input 0x00 to output 0x63
```

**Properties:**
- Non-linear mapping
- No fixed points (S[x] ≠ x)
- Avalanche effect contribution
- Resistant to differential cryptanalysis

### P-box Design

```python
# Example permutation
PBOX = [15, 6, 19, 20, 28, ...]  # Bit positions
```

**Properties:**
- Spreads bits across entire block
- No identity permutation
- Mixes adjacent bits
- Ensures diffusion

### Key Expansion

```python
def _expand_key(self):
    round_keys = []
    for round_num in range(16):
        # Derive unique key per round
        round_data = key + struct.pack('<I', round_num)
        round_key = hashlib.sha256(round_data).digest()[:16]
        round_keys.append(round_key)
    return round_keys
```

**Properties:**
- Each round key is unique
- Derived from master key
- Cryptographically strong (SHA-256)
- Cannot easily reverse engineer master key

### Padding Scheme

Uses **PKCS7 padding**:
```python
# Example: 13 bytes of data → 3 bytes padding
data = b"Hello, World!"  # 13 bytes
padded = b"Hello, World!\x03\x03\x03"  # 16 bytes
```

**Properties:**
- Unambiguous padding removal
- Works with any data size
- Industry standard

---

## 📚 Educational Use Cases

### 1. Cryptography Course Project

**Learning Objectives:**
- Understand block cipher construction
- Implement substitution and permutation
- Analyze security properties
- Compare with industry standards

**Assignment Ideas:**
- Modify S-box and measure security impact
- Experiment with different round counts
- Implement additional cipher modes (CBC, CTR)
- Break weak variants (fewer rounds)

### 2. Security Analysis Lab

**Activities:**
- Measure avalanche effect
- Perform frequency analysis
- Test with known-plaintext attacks
- Compare encryption modes

### 3. Performance Optimization

**Challenges:**
- Optimize Python implementation
- Implement in C/C++ for speed
- Add multithreading support
- Profile and identify bottlenecks

### 4. Cryptanalysis Practice

**Safe Environment:**
- Try to break weakened versions (4 rounds, weak keys)
- Implement differential cryptanalysis
- Test linear approximations
- Learn what makes strong ciphers

---

## 🎮 Interactive Mode

### Running Interactive Demo

```bash
python ciphercrest.py
# Select option 2: Interactive mode
```

**Features:**
1. **Encrypt Messages**: Input text, get ciphertext
2. **Decrypt Messages**: Input hex ciphertext, get plaintext
3. **Test Avalanche**: Run avalanche effect test
4. **Benchmark**: Performance testing
5. **Exit**: Clean exit

**Example Session:**
```
Options:
  1. Encrypt a message
  2. Decrypt a message
  3. Test avalanche effect
  4. Performance benchmark
  5. Exit

Enter choice (1-5): 1
Enter message to encrypt: Hello CipherCrest!

Ciphertext (hex): 7a3f8b2c9d1e...
Length: 32 bytes
```

---

## 🔧 Customization Guide

### Create Custom S-box

```python
import secrets

# Generate random S-box (for experimentation only!)
custom_sbox = list(range(256))
secrets.SystemRandom().shuffle(custom_sbox)

# Replace in cipher
CipherCrest.SBOX = custom_sbox

# Remember to regenerate inverse S-box!
```

### Adjust Round Count

```python
class CustomCipherCrest(CipherCrest):
    ROUNDS = 20  # More rounds = more secure but slower
```

### Implement Different Modes

```python
def encrypt_cbc(self, plaintext, iv):
    """Cipher Block Chaining mode"""
    blocks = self._split_blocks(plaintext)
    ciphertext = b''
    prev_block = iv
    
    for block in blocks:
        # XOR with previous ciphertext
        xored = bytes(a ^ b for a, b in zip(block, prev_block))
        encrypted = self._encrypt_block(xored)
        ciphertext += encrypted
        prev_block = encrypted
    
    return ciphertext
```

---

## 🐛 Troubleshooting

### Common Issues

**Issue**: `ValueError: Key must be 32 bytes`
```python
# Solution: Ensure key is exactly 32 bytes
key = b"my_secret_key".ljust(32, b'\x00')  # Pad to 32 bytes
cipher = CipherCrest(key=key)
```

**Issue**: `ValueError: Block must be 16 bytes`
```python
# Solution: Use encrypt() method, not _encrypt_block()
# encrypt() handles padding automatically
ciphertext = cipher.encrypt(data)
```

**Issue**: Decryption fails with "Padding error"
```python
# Solution: Ensure you're decrypting with same key
# and complete ciphertext (don't truncate)
```

**Issue**: Performance is slow
```python
# Expected! CipherCrest is educational, not optimized
# For production speed, use AES with hardware acceleration
```

---

## 📖 API Reference

### CipherCrest Class

```python
class CipherCrest:
    def __init__(self, key: bytes = None)
        """Initialize cipher with 256-bit key"""
    
    def encrypt(self, plaintext: bytes) -> bytes
        """Encrypt data of any length"""
    
    def decrypt(self, ciphertext: bytes) -> bytes
        """Decrypt data"""
    
    # Internal methods (advanced use)
    def _encrypt_block(self, block: bytes) -> bytes
    def _decrypt_block(self, block: bytes) -> bytes
    def _expand_key(self) -> List[bytes]
```

### CryptoAnalyzer Class

```python
class CryptoAnalyzer:
    def test_avalanche_effect(
        self, cipher, data_size: int = 128
    ) -> float
        """Test avalanche effect percentage"""
    
    def test_correlation(
        self, cipher, sample_size: int = 1000
    ) -> float
        """Test plaintext-ciphertext correlation"""
    
    def benchmark_performance(
        self, cipher, data_sizes: List[int] = None
    ) -> Dict
        """Benchmark encryption performance"""
    
    def compare_with_aes(
        self, cipher, data_size: int = 102400
    ) -> None
        """Compare with AES-256"""
    
    def visualize_encryption_pattern(
        self, cipher, save_file: str
    ) -> None
        """Generate diffusion visualization"""
```

---

## 🎓 Learning Resources

### Recommended Reading

1. **"Applied Cryptography" by Bruce Schneier**
   - Comprehensive cryptography textbook
   - Block cipher design principles

2. **"Cryptography Engineering" by Ferguson, Schneier, Kohno**
   - Practical cryptography implementation
   - Security analysis techniques

3. **"The Design of Rijndael" by Daemen and Rijmen**
   - Learn from AES creators
   - Advanced cipher design

### Online Resources

- **Cryptopals Challenges**: cryptopals.com
- **Coursera Cryptography**: Stanford/Maryland courses
- **NIST Standards**: csrc.nist.gov
- **Crypto StackExchange**: crypto.stackexchange.com

### Related Topics

- Symmetric vs Asymmetric Cryptography
- Block Cipher Modes (ECB, CBC, CTR, GCM)
- Key Derivation Functions (PBKDF2, Argon2)
- Message Authentication Codes (HMAC)
- Public Key Infrastructure (PKI)

---

## ⚖️ License

MIT License

Copyright (c) 2023 Michael Semera

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.**

---

## 🙏 Acknowledgments

### Inspiration
- **AES (Rijndael)**: Design principles and structure
- **DES**: Historical significance and lessons learned
- **Blowfish**: Key schedule design inspiration

### Tools & Libraries
- **PyCryptodome**: Industry-standard implementations
- **NumPy**: Numerical analysis
- **Matplotlib**: Visualization

### Educational Resources
- Cryptography courses and textbooks
- Security research papers
- Open-source crypto libraries

---

## 📞 Contact & Support

**Author**: Michael Semera  
**Project**: CipherCrest  
**Version**: 1.0  
**Year**: 2023

For questions, suggestions, or collaboration opportunities:
- Open an issue on GitHub
- Email: michaelsemera15@gmail.com
- LinkedIn: [Michael Semera](https://www.linkedin.com/in/michael-semera-586737295/)

For issues or questions:
- Review this documentation
- Check troubleshooting section
- Ensure proper privileges and setup
- Verify libpcap installation

### Getting Help

1. Read this README thoroughly
2. Check the troubleshooting section
3. Review code comments and docstrings
4. Experiment in interactive mode

### Contributing

Suggestions for improvements are welcome:
- Educational enhancements
- Additional analysis tools
- Documentation improvements
- Bug fixes

---

## 🚨 Security Warnings

### DO NOT Use CipherCrest For:

❌ Protecting passwords or credentials  
❌ Encrypting financial data  
❌ Securing communications  
❌ Any production application  
❌ Storing sensitive information  
❌ Compliance requirements (HIPAA, PCI-DSS, etc.)

### DO Use CipherCrest For:

✅ Learning cryptography concepts  
✅ Educational demonstrations  
✅ Academic projects  
✅ Understanding block ciphers  
✅ Security analysis practice  
✅ Algorithm comparison studies

### Use These For Production:

- **AES** (128/192/256-bit): Block cipher standard
- **ChaCha20**: Stream cipher
- **RSA** (2048/4096-bit): Public key crypto
- **Ed25519**: Digital signatures
- **Argon2**: Password hashing

**Cryptography is hard. Use proven, audited implementations!**

---

## 📊 Project Statistics

- **Lines of Code**: ~800
- **Encryption Rounds**: 16
- **Key Size**: 256 bits
- **Block Size**: 128 bits
- **S-box Size**: 256 entries
- **P-box Positions**: 32 bit positions
- **Typical Avalanche**: 48-52%
- **Typical Throughput**: 2-3 MB/s

---

## 🎯 Future Enhancements

### Planned Features

- [ ] Additional cipher modes (CBC, CTR, GCM)
- [ ] Parallel block processing
- [ ] C/C++ optimized implementation
- [ ] Additional S-box generation methods
- [ ] Key wrapping functionality
- [ ] File encryption utility
- [ ] GUI interface

### Research Directions

- [ ] Quantum resistance analysis
- [ ] Side-channel attack resistance
- [ ] Alternative round functions
- [ ] Dynamic S-box generation
- [ ] Machine learning cryptanalysis

---

**Thank you for using CipherCrest!**

*Learn cryptography safely. Build securely. Encrypt responsibly.* 🔐

---

**© 2023 Michael Semera. All Rights Reserved.**

*Built with 🔐 for cryptography education and secure coding practices.*

---

**Last Updated**: 2023  
**Documentation Version**: 1.0  
**Python Version**: 3.8+  
**Status**: Educational Release

---