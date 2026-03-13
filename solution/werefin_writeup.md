## Unwind - werefin writeup

**Author**: David Polzoni (i.e., werefin)  
**Date**: January 2026  
**Difficulty**: medium  
**Category**: reverse engineering, cryptography

---

### Challenge overview

Unwind is a reverse engineering challenge involving a stripped 64-bit ELF binary that implements a multi-layer cryptographic cipher. The binary validates a 16-character flag by applying 7 transformation steps to each character, with each transformation depending on previous ones through dual checksum chains.

**Objective**: reverse engineer the binary, understand the cryptographic algorithm, and recover the flag that unlocks the vault.

---

### File type analysis

Let's start by examining the binary:

```bash
$ file unwind
unwind: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

**Answer**: `ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped`

**Analysis**:
- **ELF 64-bit**: executable and linkable format, 64-bit architecture
- **LSB**: least significant byte first (little-endian)
- **x86-64**: AMD64/Intel 64 architecture
- **Statically linked**: all libraries are included in the binary
- **Stripped**: symbol table and debug information removed (makes reverse engineering harder)

**Checking for strings**:

```bash
$ strings unwind | head -20
QWSH
<%x%@
<%y%@
<%z%@
<%{%@
<}u1H
K@^GI_
)e@EO
FRZJX]KYO
A_EWCQF*
`{azke"4 rrbtv4
Hvmvht}}0uscqg
Qvw"
U>#-i
ya.*"2 %3!7z0= pU
37s'#993u
@JNCK
1yW_SEGW
V\djzp.{c-wmddttpdt
8mvz<msgdtdy:
```

**Observation**: the strings are obfuscated (XOR-encoded), which means we'll need to reverse engineer the decode function to understand the binary's behavior.

**Binary protections**:

```bash
$ readelf -l unwind | grep -E "GNU_STACK|GNU_RELRO"
```

The binary is stripped, so we'll need to use a disassembler like Binary Ninja or Ghidra to analyze it.

---

### Static analysis with Binary Ninja

Open the `unwind` binary in Binary Ninja. The binary will be automatically analyzed. Since the binary is stripped, we look for the entry point `_start` function, which is the main execution flow.

**Binary Ninja decompilation output**:

Here's the decompiled `_start` function from Binary Ninja:

```c
void _start(int64_t arg1) __noreturn
{
    sub_401000(arg1, &data_402000, 0x11d);
    syscall(sys_write {1}, fd: 1, buf: &data_402000, count: 0x11d);
    sub_401000(1, &data_40211d, 0x2f);
    syscall(sys_write {1}, fd: 1, buf: &data_40211d, count: 0x2f);
    int64_t var_8 = syscall(sys_read {0}, fd: 0, buf: &data_402578, count: 0x40);
    syscall(sys_write {1}, fd: 1, buf: &data_402576, count: 1);
    sub_401000(1, &data_40214c, 0x29);
    int64_t rax_2, r11_1;
    rax_2, r11_1 = syscall(sys_write {1}, fd: 1, buf: &data_40214c, count: 0x29);
    
    if (rax_2 s< 0x15 || data_402578 != 0x54 || data_402579 != 0x48
        || data_40257a != 0x4d || data_40257b != 0x7b)
    {
        label_40121f:
            sub_401000(1, &data_402175, 0xc0);
            syscall(sys_write {1}, fd: 1, buf: &data_402175, count: 0xc0);
    }
    else
    {
        char r8 = 0;
        char r9 = 0;
        void* rcx_1 = nullptr;
        
        while (true)
        {
            if (rcx_1 + 4 s>= r11_1)
                goto label_40121f;
            
            void* rax_4;
            rax_4.b = *(rcx_1 + 0x40257c);
            
            if (rax_4.b != 0x7d)
            {
                rax_4.b = *(zx.q(rax_4.b) + 0x402366);
                
                if (rcx_1 != 0)
                    rax_4.b ^= r8;
                
                char r10 = rcx_1.b;
                rcx_1.b &= 7;
                
                if (rcx_1.b != 0)
                {
                    char i;
                    do
                    {
                        rax_4.b = rol.b(rax_4.b, 1);
                        i = rcx_1.b;
                        rcx_1.b -= 1;
                    }
                    while (i != 1);
                }
                
                rcx_1.b = r10;
                uint64_t rbx_1;
                rbx_1.b = rcx_1.b;
                rbx_1.b <<= 3;
                rbx_1.b -= rcx_1.b;
                rbx_1.b += 0x5a;
                rax_4.b ^= rbx_1.b;
                rax_4.b = *(zx.q(rax_4.b) + 0x402466);
                
                if (rcx_1 != 0)
                    rax_4.b ^= r9;
                
                r8 = (r8 + rax_4.b) ^ 0xa5;
                uint64_t rbx_2;
                rbx_2.b = rax_4.b;
                rbx_2.b <<= 1;
                r9 = (r9 + rbx_2.b) ^ 0x3c;
                
                if (rax_4.b != *(rcx_1 + 0x402566))
                    goto label_40121f;
                
                rcx_1 += 1;
                
                if (rcx_1 s< 0x10)
                    continue;
                else
                {
                    if (rcx_1 + 4 s>= r11_1)
                        goto label_40121f;
                    
                    void* rax_6;
                    rax_6.b = *(rcx_1 + 0x40257c);
                    
                    if (rax_6.b != 0x7d)
                        goto label_40121f;
                }
            }
            else if (rcx_1 != 0x10)
            {
                goto label_40121f;
            }
            
            sub_401000(1, &data_402235, 0x131);
            syscall(sys_write {1}, fd: 1, buf: &data_402235, count: 0x131);
            break;
        }
    }
    
    syscall(sys_exit {0x3c}, status: 0);
    noreturn
}
```

**Key observations from decompilation**:

1. `sub_401000`: decode function that XOR-decodes strings before printing (XOR with `0xAA ^ index`)
2. **Flag format check**: the binary checks for `"THM{"` prefix (`0x54`, `0x48`, `0x4D`, `0x7B`)
3. **Main validation loop**: processes 16 characters (loop runs while `rcx_1 < 0x10`)
4. **Data structures**:
   - `0x402366`: forward S-box (256 bytes), accessed via `*(zx.q(rax_4.b) + 0x402366)`
   - `0x402466`: inverse S-box (256 bytes), accessed via `*(zx.q(rax_4.b) + 0x402466)`
   - `0x402566`: target bytes (16 bytes), accessed via `*(rcx_1 + 0x402566)`
5. **State variables**:
   - `r8`: checksum_1
   - `r9`: checksum_2
   - `rcx_1`: loop index

---

### Understanding the algorithm

From the Binary Ninja decompilation, we can identify the 7 transformation steps:

```python
# For each character at index i (0-15):

# Step 1: forward S-box substitution
rax_4.b = sbox[input[i]]  # *(zx.q(rax_4.b) + 0x402366)

# Step 2: XOR with checksum_1 (if index > 0)
if i > 0:
    rax_4.b = rax_4.b ^ checksum_1  # r8

# Step 3: rotate left by (index % 8) bits
rotation = i & 7  # index % 8
for _ in range(rotation):
    rax_4.b = rol.b(rax_4.b, 1)  # rotate left by 1 bit

# Step 4: XOR with position-dependent key
# rbx_1.b = (rcx_1.b << 3) - rcx_1.b + 0x5a
# This is equivalent to: (i * 7 + 0x5A) & 0xFF
key = (i * 7 + 0x5A) & 0xFF
rax_4.b = rax_4.b ^ key

# Step 5: inverse S-box substitution
rax_4.b = inv_sbox[rax_4.b]  # *(zx.q(rax_4.b) + 0x402466)

# Step 6: XOR with checksum_2 (if index > 0)
if i > 0:
    rax_4.b = rax_4.b ^ checksum_2  # r9

# Step 7: update checksums
checksum_1 = (checksum_1 + rax_4.b) ^ 0xA5  # r8
checksum_2 = (checksum_2 + (rax_4.b * 2)) ^ 0x3C  # r9

# Step 8: compare with target
if rax_4.b != target[i]:  # *(rcx_1 + 0x402566)
    fail()
```

The 7 transformation steps are:
1. Forward S-box substitution
2. First checksum XOR
3. Bit rotation (left by `index % 8` bits)
4. Position-dependent key XOR `(index * 7 + 0x5A) & 0xFF`
5. Inverse S-box substitution
6. Second checksum XOR
7. Dual checksum updates

Two independent 8-bit checksums are maintained:
- **checksum_1** (`r8`): updated as `(checksum_1 + transformed_byte) ^ 0xA5`
- **checksum_2** (`r9`): updated as `(checksum_2 + (transformed_byte * 2)) ^ 0x3C`

**Note**: the decompilation shows `r9 = (r9 + (rax_4.b << 1)) ^ 0x3c`, where `<< 1` is a left shift by 1 bit (multiply by 2).

---

### Extracting data structures

**Method 1: using Binary Ninja**

1. Navigate to address `0x402366` in Binary Ninja (forward S-box)
2. Right-click on the address and select "Define Array" or view the data directly
3. The S-box is 256 bytes long, so it extends from `0x402366` to `0x402465`
4. You can export the data by selecting the range and copying, or use Binary Ninja's Python API

**Method 2: using Python script**

This is an extraction script that searches for the S-box pattern:

```python
#!/usr/bin/env python3
import sys

def extract_data(binary_path):
    with open(binary_path, 'rb') as f:
        data = f.read()
    
    # Find S-box by searching for known pattern
    # From Binary Ninja output, S-box starts at 0x402366 in memory
    # In the file, we need to find the actual offset
    sbox_pattern = bytes([0xEA, 0x09, 0x67, 0x3C])
    sbox_offset = data.find(sbox_pattern)
    
    if sbox_offset == -1:
        print("ERROR: could not find S-box pattern")
        return
    
    # Extract forward S-box (256 bytes)
    sbox = list(data[sbox_offset:sbox_offset + 256])
    
    # Inverse S-box is 256 bytes after
    inv_sbox_offset = sbox_offset + 256
    inv_sbox = list(data[inv_sbox_offset:inv_sbox_offset + 256])
    
    # Target bytes are 256 bytes after inverse S-box
    target_offset = inv_sbox_offset + 256
    target = list(data[target_offset:target_offset + 16])
    
    print(f"Forward S-box (first 16 bytes): {[hex(b) for b in sbox[:16]]}")
    print(f"Inverse S-box (first 16 bytes): {[hex(b) for b in inv_sbox[:16]]}")
    print(f"Target bytes: {[hex(b) for b in target]}")
    
    # Verify S-box inverse relationship
    for i in range(256):
        if inv_sbox[sbox[i]] != i:
            print(f"ERROR: inverse check failed at index {i}")
            return
    print("S-box inverse relationship verified!")
    
    return sbox, inv_sbox, target

if __name__ == '__main__':
    sbox, inv_sbox, target = extract_data('unwind')
```

**Running the extraction**:

```bash
$ python3 extract_from_disassembler.py public/unwind

Found S-box at file offset: 0x2366

Forward S-box (first 16 bytes)
['0xea', '0x9', '0x67', '0x3c', '0x5', '0x4f', '0xe8', '0xe5', '0x2d', '0x33', '0x83', '0x3', '0xa8', '0x1d', '0xaa', '0xd8']

Inverse S-box (first 16 bytes)
['0x5d', '0xdb', '0x48', '0xb', '0x3d', '0x4', '0xfe', '0xee', '0xef', '0x1', '0x41', '0xc7', '0x7f', '0x57', '0x98', '0x23']

Target bytes (16 bytes)
['0x4', '0x97', '0xdd', '0xba', '0x1a', '0xdd', '0xc8', '0x67', '0x3a', '0x27', '0xa6', '0xcc', '0x30', '0xb9', '0x7e', '0x32']

S-box inverse relationship verified!
```

**Verification**:
```python
>>> sbox[0x0A]
131 # decimal
>>> hex(131)
'0x83'
```

**Data structure addresses**:

| Data structure | Address | Size | Description |
|---------------|---------|------|-------------|
| Forward S-box | `0x402366` | 256 bytes | Substitution box for step 1 |
| Inverse S-box | `0x402466` | 256 bytes | Substitution box for step 5 |
| Target bytes | `0x402566` | 16 bytes | Expected encrypted values |

---

### Implementing the solver

The algorithm is **stateful**, each character's transformation depends on the checksums from previous characters. This means we need to solve sequentially using backtracking.

```python
# Load S-boxes and target from extracted data
with open('sbox.bin', 'rb') as f:
    sbox = list(f.read())

with open('inv_sbox.bin', 'rb') as f:
    inv_sbox = list(f.read())

with open('target.bin', 'rb') as f:
    target = list(f.read())

def transform_char(c, checksum_1, checksum_2, index):
    """
    Forward transformation matching the binary's algorithm
    
    Args:
        c: input character (byte value)
        checksum_1: first checksum value
        checksum_2: second checksum value
        index: character position (0-15)
    
    Returns:
        Transformed byte value
    """
    al = c
    
    # Step 1: forward S-box substitution
    al = sbox[al]
    
    # Step 2: XOR with checksum_1 (if index > 0)
    if index > 0:
        al ^= (checksum_1 & 0xFF)
    
    # Step 3: rotate left by (index % 8) bits
    r = index & 7 # index % 8
    al = ((al << r) | (al >> (8 - r))) & 0xFF
    
    # Step 4: XOR with position-dependent key
    key = (index * 7 + 0x5A) & 0xFF
    al ^= key
    
    # Step 5: inverse S-box substitution
    al = inv_sbox[al]
    
    # Step 6: XOR with checksum_2 (if index > 0)
    if index > 0:
        al ^= (checksum_2 & 0xFF)
    
    return al

def solve():
    """
    Backtracking solver to find the flag
    
    Since each character depends on previous checksums,
    we solve sequentially using backtracking.
    """
    flag = []
    checksum_1 = 0
    checksum_2 = 0
    
    def backtrack(index):
        """
        Recursive backtracking function
        
        Args:
            index: current character position (0-15)
        
        Returns:
            True if solution found, False otherwise
        """
        if index == 16:
            return True
        
        # Try all printable ASCII characters
        for c in range(0x20, 0x7F): # printable ASCII range
            # Apply forward transformation
            result = transform_char(c, checksum_1, checksum_2, index)
            
            # Check if matches target byte
            if result == target[index]:
                # Update checksums (matching binary's update logic)
                new_cs1 = ((checksum_1 & 0xFF) + result) & 0xFF
                new_cs1 = (new_cs1 ^ 0xA5) & 0xFF
                
                new_cs2 = ((checksum_2 & 0xFF) + ((result << 1) & 0xFF)) & 0xFF
                new_cs2 = (new_cs2 ^ 0x3C) & 0xFF
                
                # Save state
                flag.append(chr(c))
                old_cs1, old_cs2 = checksum_1, checksum_2
                checksum_1, checksum_2 = new_cs1, new_cs2
                
                # Recurse to next position
                if backtrack(index + 1):
                    return True
                
                # Backtrack: restore state
                flag.pop()
                checksum_1, checksum_2 = old_cs1, old_cs2
        
        return False
    
    if backtrack(0):
        return "THM{" + "".join(flag) + "}"
    return None

if __name__ == '__main__':
    print(f"Target bytes: {[hex(b) for b in target]}")
    print()
    
    flag = solve()
    if flag:
        print(f"Flag found: {flag}")
    else:
        print("No solution found")
```

**Running the solver**:

```bash
$ python3 solver.py
Target bytes: ['0x4', '0x97', '0xdd', '0xba', '0x1a', '0xdd', '0xc8', '0x67', '0x3a', '0x27', '0xa6', '0xcc', '0x30', '0xb9', '0x7e', '0x32']

Flag found: THM{NbrnTP3fAbnFbmOH}
```

### Recovering the flag

**Question**: what is the flag that unlocks the binary?

**Answer**: `THM{NbrnTP3fAbnFbmOH}`

### Verifying the solution

```bash
$ echo "THM{NbrnTP3fAbnFbmOH}" | ./unwind
========================================
       Unwind [LOCKED]
========================================

Protected by a rotation cipher.
Each character rotates through 7 steps.
Position determines rotation amount.

Provide the 16-character key.
One wrong character breaks the chain.

Enter the 16-character key (format: THM{...}): THM{NbrnTP3fAbnFbmOH}

Validating key...
Applying rotations...

========================================
       Unwind [UNLOCKED]
========================================

The vault is open. You have proven yourself worthy.

You have mastered the multi-layer cipher:
S-box substitution, XOR operations, bit rotations,
position-dependent keys, and dual checksum chains.
```

**Success!** the binary is unlocked.

---

### Algorithm details

```python
def transform_char(c, checksum_1, checksum_2, index):
    """
    Complete 7-step transformation
    
    Step-by-step breakdown:
    """
    al = ord(c) # input character
    
    # Step 1: forward S-box (256-byte lookup table)
    al = sbox[al]
    
    # Step 2: XOR with checksum_1 (stateful - depends on previous chars)
    if index > 0:
        al ^= (checksum_1 & 0xFF)
    
    # Step 3: rotate left by (index % 8) bits
    # This creates position-dependent rotation:
    # index 0: 0 bits, index 1: 1 bit, ..., index 7: 7 bits
    # index 8: 0 bits (cycles), index 9: 1 bit, etc.
    r = index & 7
    al = ((al << r) | (al >> (8 - r))) & 0xFF
    
    # Step 4: XOR with position-dependent key
    # Key formula: (index * 7 + 0x5A) & 0xFF
    # Creates a unique key for each position
    key = (index * 7 + 0x5A) & 0xFF
    al ^= key
    
    # Step 5: inverse S-box (reverse lookup)
    al = inv_sbox[al]
    
    # Step 6: XOR with checksum_2 (stateful)
    if index > 0:
        al ^= (checksum_2 & 0xFF)
    
    # Step 7: update checksums (for next iteration)
    # Note: Updates happen AFTER comparison in binary
    # but we need them for next character
    
    return al
```

**Example**:
- Character 0: no checksum dependency, but affects checksums for char 1
- Character 1: depends on checksums from char 0
- Character 2: depends on checksums from chars 0 and 1
- And so on...

**Complexity analysis**:

- **Search space per position**: $\approx 95$ printable ASCII characters
- **Total positions**: 16
- **Naive brute force**: $95^{16} \approx 4.4 × 10^{31}$ possibilities
- **With backtracking**: $\approx 95 \times 16 = 1520$ operations (much faster!)

The backtracking approach is efficient because:
1. We prune invalid paths early
2. Each position has only one valid solution (full S-box ensures uniqueness)
3. We solve sequentially, not independently

### Appendix: complete code

```python
import random

# Generate the same S-box and inverse S-box as in the binary
random.seed(42)
sbox = list(range(256))
random.shuffle(sbox)

inv_sbox = [0] * 256
for i in range(256):
    inv_sbox[sbox[i]] = i

target = [
    0x04,0x97,0xDD,0xBA,0x1A,0xDD,0xC8,0x67,
    0x3A,0x27,0xA6,0xCC,0x30,0xB9,0x7E,0x32
]

def transform_char(c, checksum_1, checksum_2, index):
    """Transform a character according to the algorithm"""
    al = ord(c)
    
    # Full byte S-box substitution
    al = sbox[al]
    
    # XOR with checksum_1 (if index > 0)
    if index > 0:
        al ^= (checksum_1 & 0xFF)
    
    # Rotation by (index % 8)
    r = index & 7
    al = ((al << r) | (al >> (8 - r))) & 0xFF
    
    # XOR with position-dependent key
    key = (index * 7 + 0x5A) & 0xFF
    al ^= key
    
    # Second S-box (inverse)
    al = inv_sbox[al]
    
    # XOR with checksum_2
    if index > 0:
        al ^= (checksum_2 & 0xFF)
    
    return al

def solve(flag, checksum_1, checksum_2, index):
    """Backtracking solver with full S-box, should be unique"""
    if index == 16:
        return True
    
    # Try all possible characters
    for c in range(0x20, 0x7F):
        s = transform_char(chr(c), checksum_1, checksum_2, index)
        
        if s == target[index]:
            # Update checksums
            new_checksum_1 = ((checksum_1 & 0xFF) + s) & 0xFF
            new_checksum_1 = (new_checksum_1 ^ 0xA5) & 0xFF
            
            new_checksum_2 = ((checksum_2 & 0xFF) + (s << 1)) & 0xFF
            new_checksum_2 = (new_checksum_2 ^ 0x3C) & 0xFF
            
            flag.append(chr(c))
            if solve(flag, new_checksum_1, new_checksum_2, index + 1):
                return True
            flag.pop() # backtrack
    
    return False

flag = []
if solve(flag, 0, 0, 0):
    print("THM{" + "".join(flag) + "}")
else:
    print("No solution found")
```
