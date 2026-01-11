import random

# Generate a deterministic 256-byte S-box
random.seed(42)
sbox = list(range(256))
random.shuffle(sbox)

# Generate inverse S-box for second round
inv_sbox = [0] * 256
for i in range(256):
    inv_sbox[sbox[i]] = i

flag = "NbrnTP3fAbnFbmOH"

checksum_1 = 0
checksum_2 = 0
out = []

for i, ch in enumerate(flag):
    al = ord(ch)
    
    # Full byte S-box substitution
    al = sbox[al]
    
    # XOR with first checksum (if index > 0)
    if i > 0:
        al ^= (checksum_1 & 0xFF)
    
    # Rotation by (index % 8) for more variation
    r = i & 7
    al = ((al << r) | (al >> (8 - r))) & 0xFF
    
    # XOR with position-dependent key
    key = (i * 7 + 0x5A) & 0xFF
    al ^= key
    
    # Second S-box (inverse) for added complexity
    al = inv_sbox[al]
    
    # XOR with second checksum
    if i > 0:
        al ^= (checksum_2 & 0xFF)
    
    # Update checksums
    checksum_1 = ((checksum_1 & 0xFF) + al) & 0xFF
    checksum_1 = (checksum_1 ^ 0xA5) & 0xFF
    
    checksum_2 = ((checksum_2 & 0xFF) + (al << 1)) & 0xFF
    checksum_2 = (checksum_2 ^ 0x3C) & 0xFF
    
    out.append(al)

print("S-box (first 16 values):", [hex(b) for b in sbox[:16]])
print("Target bytes:")
print(", ".join(f"0x{b:02X}" for b in out))