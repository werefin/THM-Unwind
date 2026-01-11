#!/bin/bash

echo "Testing bounds checking and buffer overflow protection"
echo ""

BINARY="./public/unwind"

# Test buffer size edge cases
echo "Test 1: input exactly at buffer limit (64 bytes)"
python3 -c "print('THM{' + 'A' * 59 + '}')" | wc -c
python3 -c "print('THM{' + 'A' * 59 + '}')" | timeout 2 $BINARY 2>&1 | head -3
echo ""

echo "Test 2: input over buffer limit (65+ bytes)"
python3 -c "print('THM{' + 'A' * 60 + '}')" | wc -c
python3 -c "print('THM{' + 'A' * 60 + '}')" | timeout 2 $BINARY 2>&1 | head -3
echo ""

echo "Test 3: minimum valid input (21 bytes)"
echo "THM{12345678901234}" | wc -c
echo "THM{12345678901234}" | timeout 2 $BINARY 2>&1 | head -3
echo ""

echo "Test 4: one byte less than minimum (20 bytes)"
echo "THM{1234567890123}" | wc -c
echo "THM{1234567890123}" | timeout 2 $BINARY 2>&1 | head -3
echo ""

echo "Test 5: check if read syscall limits to 64 bytes"
python3 -c "print('THM{' + 'A' * 1000 + '}')" | timeout 2 $BINARY 2>&1 | head -3
echo ""

echo "Test 6: verify bounds check prevents out-of-bounds access"
# This should fail without crashing
echo "THM{AAAAAAAAAAAAAAAA}" | timeout 2 $BINARY 2>&1 | grep -E "(Access denied|UNLOCKED|Segmentation|fault)" | head -1
echo ""

echo "Bounds testing complete"
