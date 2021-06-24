# About

DISA is a full, compact x86 disassembler designed
for internal application use.

It is based on the intel references at:
http://ref.x86asm.net/coder32.html

It features everything except for SIMD instructions,
which I intend to add support for.
I hope to add support for x64 as well.



# Usage

To use DISA, simply call disa_load() once, to initialise the disassembler.

Take a look at the Examples folder for help on starting out with DISA.

Here is a run-down of things:
Let's assume the address 0xDEADBEEF contains this instruction:
mov eax,[ebp+8];

First, we read it into a variable:

const auto inst = disa_read(0xDEADBEEF); // store the instruction information into `inst`

Let's say, we're hoping to identify eax, ebp, and 8, programatically.
The first thing we do is make sure it contains a source and destination operand:

if (inst.flags & OP_SRC_DEST)
{
  // ...
}


Okay, now, we can go right ahead and read the values in src(first half), and dest(second half):

if (inst.flags & OP_SRC_DEST)
{
  std::cout << "first register used in source: " << inst.src().reg[0] << std::endl; // 0 ***
  std::cout << "first register used in destination: " << inst.dest().reg[0] << std::endl; // 5 ***
  std::cout << "8-bit offset used in destination: " << inst.dest().imm8 << std::endl; // 8
}


***
Remember, registers are stored as a number which goes in this order:
0 - EAX <---
1 - ECX
2 - EDX
3 - EBX
4 - ESP
5 - EBP <---
6 - ESI
7 - EDI


An operand that has [ebp+8] (or, [ebp+08]) will have an `imm8` offset of 8. 
An operand that has [ebp+0008] will have an `imm16` offset of 8.
An operand that has [ebp+00000008] will have an `imm32` offset of 8.

Now, if it's a constant value in the case of:
mov eax,[00A7120C]
this is called a `disp32` value.
Unlike imm32, it is not an offset of a register but a direct memory address instead.

Hopefully this is enough to grasp the basics of DISA
Until I write up a proper documentation

