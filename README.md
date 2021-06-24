# About

DISA is a full, compact x86 disassembler designed
for internal application use.

It is based on the intel references at:
http://ref.x86asm.net/coder32.html

It features everything except for SIMD instructions,
which I intend to add support for.
I plan to add support for x64 as well.



# Usage

To use DISA, simply call disa_load() once, to initialise the disassembler.<br>
ALWAYS REMEMBER to do this before calling any other DISA functions.

Take a look at the Examples folder for help on starting out with DISA.

Here is a run-down of things:<br>
Let's assume the address 0xDEADBEEF contains this instruction:<br>
`mov eax,[ebp+8];`

First, we read it into a variable:<br>
`const auto inst = disa_read(0xDEADBEEF); // 'inst' contains info about the instruction at this address`

We can print the raw text translation of this instruction by doing:<br>
`std::cout << inst.data << std::endl; // "mov eax,[ebp+08]"`

How can we use code to grab information like 'eax', 'ebp', or +8, programatically?<br>
The first thing we would do is make sure it contains both a source and destination operand:
```
if (inst.flags & OP_SRC_DEST)
{
  // ...
}
```

Okay, now, we can go right ahead and read the values in the source and destination like so:
```
if (inst.flags & OP_SRC_DEST)
{
  std::cout << "first register used in source: " << inst.src().reg[0] << std::endl; // 0 ***
  std::cout << "first register used in destination: " << inst.dest().reg[0] << std::endl; // 5 ***
  std::cout << "8-bit offset used in destination: " << inst.dest().imm8 << std::endl; // 8
  
  std::cout << "The size of the instruction is: " << inst.len << " bytes!" << std::endl;
  
  if (inst.dest().reg[0] == R32_EBP)
  {
    std::cout << "the destination operand uses EBP!" << std::endl;
  }
}
```

src() and dest() access the first and second operands of the instruction automatically.
and reg is a table containing the registers used in this part of the instruction.

So in a 2-operand instruction, source is the first half, destination is the second half.

***
Remember, registers are stored as a number which goes in this order:<br>

0 - EAX <---<br>
1 - ECX<br>
2 - EDX<br>
3 - EBX<br>
4 - ESP<br>
5 - EBP <---<br>
6 - ESI<br>
7 - EDI<br>

You can always use the enums for it, like R32_EBP or R32_EAX.

An operand that has [ebp+8] (or, [ebp+08]) will have an 'imm8' offset of 8.<br>
An operand that has [ebp+0008] will have an 'imm16' offset of 8.<br>
An operand that has [ebp+00000008] will have an 'imm32' offset of 8.<br>

Now, if it's a constant value in the case of:<br>
`mov eax,[00A7120C]`

This is called a 'disp32' value.<br>
You can grab this value by doing: inst.dest().disp32.<br>
Unlike imm32, it is not an offset of a register, but a direct memory address instead.<br>

There are many other members of the operand class I'll try to explain more in-depth<br>
Hopefully this is enough to grasp the basics of disassembling with DISA<br>
Until I write up a full documentation<br>

