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

Here is a run-down of things:<br>
Let's assume the address 0xDEADBEEF contains this instruction:<br>
`mov eax,[ebp+8];`

First, we read it into a variable:<br>
`const auto inst = disa_read(0xDEADBEEF); // store the instruction information into 'inst'`

We can print the raw text translation of this instruction by doing:<br>
`std::cout << inst.data << std::endl; // "mov eax,[ebp+08]"`

Now let's say, we're hoping to identify eax, ebp, and 8, programatically.<br>
The first thing we do is make sure it contains a source and destination operand:
```
if (inst.flags & OP_SRC_DEST)
{
  // ...
}
```

Okay, now, we can go right ahead and read the values in src(first half), and dest(second half):
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

