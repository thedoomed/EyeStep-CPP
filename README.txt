# About

EyeStep is a full and compact intel x86 disassembler designed
for both internal(DLL) and executable(EXE) applications.

It is original and table-based from the insight/references provided at:
http://ref.x86asm.net/coder32.html

It features everything except for SIMD instructions
but I intend to add support for that and possibly x64
in the future.



# Usage

To use EyeStep you simply include eyestep.h where needed.
To initialise EyeStep in A DLL, you must place this
FIRST before you do anything:
EyeStep::open(GetCurrentProcess());

If you want to initialise EyeStep in an EXE, you do this instead:
EyeStep::open("ProcessNameHere.exe");


Use EyeStep::read(address) to translate the instruction at 'address'.

auto instr = EyeStep::read(0x12000000); // returns an 'EyeStep::inst' object
std::cout << instr.data << std::endl; // displays its disassembled output


You can view a range of instructions like so:

uint32_t from = 0x12000000;
uint32_t to = from + 100; // disassemble instructions from point A to point B
for (EyeStep::inst instr : EyeStep::read_range(from, to))
{
    std::cout << instr.data << std::endl;
}


Or a set amount of instructions:

uint32_t from = 0x12000000;
size_t number_of_instructions = 10;
for (EyeStep::inst instr : EyeStep::read(from, number_of_instructions))
{
    std::cout << instr.data << std::endl;
}



The EyeStep::inst / instruction class contains the following members:

data - text translation of disassembly
len - length of instruction
pre_flags - OR'd flags for instruction prefixes
address - location in memory of this instruction (whatever you called ReadInstruction with)
operands - table of operands used

'operands' contains up to 4 operands (blank by default) per instruction 
for example, mov eax,[ebx] contains 2 operands (source & destination)
For the source operand you can use operands[0], or inst.source()
For destination, you can use operands[1], or inst.destination()


The operand class contains the following:

opmode - this is the mode, or, type of operand. There are many of these. SEE BELOW***
reg - table of registers in this operand (any bit size)
mul - multiplier used in SIB byte
rel8/rel16/rel32 - the relative offset used in this operand --- Example: call 011C0D20 (...rel32 would be 011C0D20)
imm8/imm16/imm32 - the offset value used in this operand --- Example: mov eax,[ebx+0120CDD0]
disp8/disp16/disp32 - the constant value used in this operand --- Example: mov eax,DEADBEEF


*** Here are examples of what an instruction's opmodes would be:

mov eax,[ebx+04] \/\/\/
operands[0].opmode = r16_32/r32 // first operand is just a 32-bit register
operands[1].opmode = r_m16_32/r_m32 // second operand includes modes (brackets, offsets, etc.)

mov [ebx+04],eax \/\/\/
operands[0].opmode = r_m16_32/r_m32
operands[1].opmode = r16_32/r32

Understanding what modes are will drastically help gain more control of instructions.
They are defined by the byte being read.
One byte can determine what register is being used in BOTH operands.

call 0110CBF0 \/\/\/
operands[0].opmode = rel32

mov eax,10000000 \/\/\/
operands[0].opmode = r32
operands[1].opmode = disp32
operands[1].disp32 = 10000000 // constant/number value

mov eax,[10000000] \/\/\/
operands[0].opmode = r32
operands[1].opmode = imm32
operands[1].imm32 = 10000000 // offset/location in memory being read into eax


# For more help on using EyeStep to disassemble instructions
please contact Celery#7902

