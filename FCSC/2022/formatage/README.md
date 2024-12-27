## Level: Hard

### Challenge


#### TL;DR

- Abuse pointers in form of `**` which points to stack addresses to overwrite saved rip of printf to return to main

- Set up read-what-where primitive by creating a pointer table and write ROP on stack via pointer table because our input is stored in heap...

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

> classic fmt but with only 1 shot...


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

I followed voydstack's ![writeup](https://hackropole.fr/en/writeups/fcsc2022-pwn-formatage/202b3b8a-fa8d-4a37-b342-967db364d9ee/) but it still took me 2 days to solve...

his write-up is pretty good and im not going to waste my time inventing the wheel again...

here some takeaways for future use:

![ptable](https://github.com/user-attachments/assets/08319ac5-d387-4afb-a54f-007cb17aadea)
> general concept of double pointers, creating ptable -> ROP on the stack...

- make the double pointer trick work by `"%c" * (pointer_offset - 2 ) + f"%{target - (pointer_offset - 2)}c" + "%hn"` 
> > not sure about the first part, could it be printf cache??

> > also no need to do this everytime... do it once and use `$` to overwrite again 






