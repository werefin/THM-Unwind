#!/bin/sh
set -e
nasm -f elf64 unwind.asm -o unwind.o
ld unwind.o -o unwind
strip unwind
echo "Unwind built"