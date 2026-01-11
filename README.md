## Unwind - TryHackMe werefin room

A reverse engineering challenge featuring a crypto-based binary that validates flags using a stateful cryptographic transformation.

### Challenge Description

**Welcome to Unwind - a secure system protected by a cryptographic system based on bit rotations.**

The system uses a multi-layer encryption system where each character undergoes **7 transformations** through substitution boxes and rotations. The rotations are position-dependent, each character rotates by a different amount based on its position in the key. The algorithm creates a complex dependency chain where each character depends on all previous ones (i.e., one wrong character breaks the rotation chain).

**Objective**: reverse engineer the binary, understand the rotation cipher, and unlock Unwind to discover the secrets of rotation-based cryptography.

### Files

**Challenge files**:
- `public/unwind` - the challenge binary (stripped 64-bit ELF)

**Solution files**:
- `solution/solver.py` - Python solver script using backtracking
- `solution/generate_target.py` - script to generate target bytes for a given flag
- `solution/werefin_writeup.md` - detailed writeup with Binary Ninja analysis

**Helper scripts**:
- `extract_from_disassembler.py` - script to extract S-boxes and target bytes from the binary
- `test_vulnerabilities.sh` - comprehensive security vulnerability testing script
- `test_bounds.sh` - bounds checking and buffer overflow protection tests

**Data files**:
- `sbox.bin` - forward S-box (256 bytes)
- `inv_sbox.bin` - inverse S-box (256 bytes)
- `target.bin` - target bytes (16 bytes) for flag validation

**Documentation**:
- `security_assessment.md` - Security assessment report

### Challenge details

- **Difficulty**: medium-hard
- **Category**: reverse Engineering, cryptography
- **Flag format**: `THM{...}` (16 characters inside braces)
- **Architecture**: x86-64 Linux ELF
- **Protections**: stripped, no symbols
- **Time Estimate**: 1-2 hours (depending on experience)

### Algorithm overview

The system validates flags using a sophisticated multi-step cryptographic transformation:

1. **Full-byte S-box substitution**: each character is transformed through a 256-byte S-box
2. **First checksum XOR**: each byte (except the first) is XORed with checksum_1
3. **Bit rotation**: each byte is rotated left by `(index % 8)` bits
4. **Position-dependent key XOR**: XOR with `(index * 7 + 0x5A) & 0xFF`
5. **Inverse S-box substitution**: apply inverse S-box lookup
6. **Second checksum XOR**: each byte (except the first) is XORed with checksum_2
7. **Dual checksum update**: both checksums are updated independently
8. **Validation**: the transformed byte is compared against a hardcoded target

This creates a strong dependency chain where each byte depends on all previous bytes. The use of full 256-byte S-boxes ensures **only one unique solution exists**.

### Solving the challenge

Participants should:

1. Analyze the binary using disassemblers (i.e., Binary Ninja or Ghidra)
2. Identify the validation algorithm
3. Extract the S-box and target bytes using `extract_from_disassembler.py` or manually
4. Re-implement the algorithm in a scripting language
5. Use backtracking to solve for the flag

**Note**: the full 256-byte S-boxes ensure only one unique solution exists (no collisions).

### Testing

**Test the binary**:
```bash
echo "THM{your_flag_here}" | ./public/unwind
```

**Run security tests**:
```bash
# Test for vulnerabilities
./test_vulnerabilities.sh

# Test bounds checking
./test_bounds.sh
```

**Extract data structures**:
```bash
# Extract S-boxes and target bytes
python3 extract_from_disassembler.py public/unwind
```

**Run the solver**:
```bash
python3 solution/solver.py
```

### Building

To rebuild the binary:
```bash
cd build
./build.sh
```

### Security

The binary has been tested for security vulnerabilities. See `security_assessment.md` for detailed security analysis. Key security features:

- ✅ Buffer overflow protection (64-byte read limit)
- ✅ Input validation (minimum length, format checks)
- ✅ Bounds checking before all buffer accesses
- ✅ Error handling (no crashes on malicious input)
- ✅ Injection attack resistance (command injection, format strings, etc.)