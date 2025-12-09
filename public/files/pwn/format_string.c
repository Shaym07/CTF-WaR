// Format String Challenge
// Compile: gcc -o format format_string.c

#include <stdio.h>
#include <string.h>

int secret = 0;
char flag[] = "WOW{f0rm4t_str1ng_l34k}";

void vuln() {
    char buffer[100];
    printf("Enter your input: ");
    fgets(buffer, sizeof(buffer), stdin);

    // VULNERABLE: user input used directly as format string
    printf(buffer);

    printf("\n");

    if (secret == 0xdeadbeef) {
        printf("Flag: %s\n", flag);
    }
}

int main() {
    printf("=== Format String Challenge ===\n");
    printf("Address of secret: %p\n", &secret);
    printf("Current value of secret: 0x%x\n", secret);
    printf("Target value: 0xdeadbeef\n\n");

    vuln();

    return 0;
}

/*
Exploits:
1. Leak stack: %p %p %p %p %p %p
2. Read memory: %s with address
3. Write memory: %n to write number of chars printed

Example payload to leak: AAAA%08x.%08x.%08x.%08x
*/
