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
