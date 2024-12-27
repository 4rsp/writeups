## Level: Hard

### Challenge


#### TL;DR

- Abuse pointers in form of `**` which points to stack addresses to overwrite saved_rip of printf to return to main
- Set up read-what-where primitive by creating a pointer table and write ROP on stack via pointer table...
- and return to our ROP chain on the stack
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
