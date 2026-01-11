#!/bin/bash

echo "Testing for vulnerabilities in unwind binary"
echo ""

BINARY="./public/unwind"

# Test 1: very long input (buffer overflow)
echo "Test 1: very long input (buffer overflow)"
echo "THM{$(python3 -c "print('A' * 1000)")}" | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 2: null bytes
echo "Test 2: null bytes in input"
printf "THM{\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00}" | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 3: control characters
echo "Test 3: control characters (newlines, tabs, etc.)"
printf "THM{\x0A\x0D\x09\x1B\x7F\x00\x01\x02\x03\x04\x05\x06\x07\x08}" | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 4: special shell characters
echo "Test 4: special shell characters"
echo 'THM{;rm -rf /;ls}' | timeout 2 $BINARY 2>&1 | head -5
echo 'THM{$(whoami)}' | timeout 2 $BINARY 2>&1 | head -5
echo 'THM{`id`}' | timeout 2 $BINARY 2>&1 | head -5
echo 'THM{||ping -c 1 127.0.0.1}' | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 5: format string attempts
echo "Test 5: format string attempts"
echo 'THM{%x%x%x%x%x}' | timeout 2 $BINARY 2>&1 | head -5
echo 'THM{%n%n%n%n%n}' | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 6: Unicode/UTF-8
echo "Test 6: Unicode/UTF-8 characters"
echo 'THM{测试测试测试测试}' | timeout 2 $BINARY 2>&1 | head -5
echo 'THM{🚀🚀🚀🚀🚀🚀🚀🚀}' | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 7: path traversal attempts
echo "Test 7: path traversal attempts"
echo 'THM{../../etc/passwd}' | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 8: SQL injection style (though not applicable)
echo "Test 8: SQL injection style patterns"
echo "THM{' OR '1'='1}" | timeout 2 $BINARY 2>&1 | head -5
echo "THM{'; DROP TABLE users; --}" | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 9: very short input
echo "Test 9: very short input"
echo "THM{}" | timeout 2 $BINARY 2>&1 | head -5
echo "THM{1}" | timeout 2 $BINARY 2>&1 | head -5
echo "THM{12}" | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 10: missing prefix
echo "Test 10: missing THM{ prefix"
echo "NbrnTP3fAbnFbmOH}" | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 11: missing closing brace
echo "Test 11: missing closing brace"
echo "THM{NbrnTP3fAbnFbmOH" | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 12: extra characters after }
echo "Test 12: extra characters after }"
echo "THM{NbrnTP3fAbnFbmOH}EXTRA" | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 13: multiple braces
echo "Test 13: multiple braces"
echo "THM{{{{{{{{{{{{{{{{}}}}}}}}}}}}}}}}" | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 14: binary data
echo "Test 14: binary data"
python3 -c "import sys; sys.stdout.buffer.write(b'THM{' + bytes(range(16)) + b'}')" | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 15: empty input
echo "Test 15: empty input"
echo "" | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 16: only whitespace
echo "Test 16: only whitespace"
echo "   " | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 17: memory exhaustion attempt (very large input)
echo "Test 17: memory exhaustion (10KB input)"
echo "THM{$(python3 -c "print('A' * 10000)")}" | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 18: integer overflow attempts in input
echo "Test 18: integer overflow patterns"
echo "THM{9999999999999999}" | timeout 2 $BINARY 2>&1 | head -5
echo ""

# Test 19: check if binary crashes or hangs
echo "Test 19: check for crashes/hangs"
echo "THM{AAAAAAAAAAAAAAAA}" | timeout 2 $BINARY 2>&1 > /dev/null && echo "Binary handled input without crash" || echo "Binary may have crashed or hung"
echo ""

echo "Vulnerability testing complete"
