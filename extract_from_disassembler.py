#!/usr/bin/env python3
"""
Script to extract S-boxes and target bytes from the unwind binary.
Use this after finding the addresses in Binary Ninja or Ghidra.
"""

import sys

def extract_data(binary_path):
    with open(binary_path, 'rb') as f:
        data = f.read()
    
    # Find .data section (usually starts around 0x402000 in loaded binary)
    # But in the file, we need to find the actual offset
    
    # Method 1: search for known S-box pattern
    # S-box starts with: 0xEA, 0x09, 0x67, 0x3C
    sbox_pattern = bytes([0xEA, 0x09, 0x67, 0x3C])
    sbox_offset = data.find(sbox_pattern)
    
    if sbox_offset == -1:
        print("ERROR: could not find S-box pattern in binary")
        print("Please use Binary Ninja or Ghidra to find the exact addresses and extract manually")
        return
    
    print(f"Found S-box at file offset: 0x{sbox_offset:x}")
    
    # Extract forward S-box (256 bytes)
    sbox = list(data[sbox_offset:sbox_offset + 256])
    
    # Inverse S-box should be 256 bytes after
    inv_sbox_offset = sbox_offset + 256
    inv_sbox = list(data[inv_sbox_offset:inv_sbox_offset + 256])
    
    # Target bytes should be 256 bytes after inverse S-box
    target_offset = inv_sbox_offset + 256
    target = list(data[target_offset:target_offset + 16])
    
    print("\nForward S-box (first 16 bytes)")
    print([hex(b) for b in sbox[:16]])
    
    print("\nInverse S-box (first 16 bytes)")
    print([hex(b) for b in inv_sbox[:16]])
    
    print("\nTarget bytes (16 bytes)")
    print([hex(b) for b in target])
    
    # Save to files
    with open('sbox.bin', 'wb') as f:
        f.write(bytes(sbox))
    
    with open('inv_sbox.bin', 'wb') as f:
        f.write(bytes(inv_sbox))
    
    with open('target.bin', 'wb') as f:
        f.write(bytes(target))
    
    print("\nSaved to files")
    print("sbox.bin - Forward S-box (256 bytes)")
    print("inv_sbox.bin - Inverse S-box (256 bytes)")
    print("target.bin - Target bytes (16 bytes)")
    
    # Also generate Python code
    print("\nPython code snippet")
    print("sbox = " + str(sbox))
    print("inv_sbox = " + str(inv_sbox))
    print("target = " + str(target))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 extract_from_ghidra.py <path_to_unwind_binary>")
        print("Example: python3 extract_from_ghidra.py public/unwind")
        sys.exit(1)
    
    extract_data(sys.argv[1])
