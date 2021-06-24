#include "disasm.hpp"
#include <sstream>
#include <iomanip>

const enum disa_optypes : std::uint8_t
{
	AL,
	AH,
	AX,
	EAX,
	ECX,
	EDX,
	ESP,
	EBP,
	CL,
	CX,
	DX,
	Sreg,
	ptr16_32,
	Flags,
	EFlags,
	ES,
	CS,
	DS,
	SS,
	FS,
	GS,
	one,
	r8,
	r16,
	r16_32,
	r32,
	r64,
	r_m8,
	r_m16,
	r_m16_32,
	r_m16_m32,
	r_m32,
	moffs8,
	moffs16_32,
	m16_32_and_16_32,
	m,
	m8,
	m14_28,
	m16,
	m16_32,
	m16_int,
	m32,
	m32_int,
	m32real,
	m64,
	m64real,
	m80real,
	m80dec,
	m94_108,
	m128,
	m512,
	rel8,
	rel16,
	rel16_32,
	rel32,
	imm8,
	imm16,
	imm16_32,
	imm32,
	mm,
	mm_m64,
	xmm,
	xmm0,
	xmm_m32,
	xmm_m64,
	xmm_m128,
	STi,
	ST1,
	ST2,
	ST,
	LDTR,
	GDTR,
	IDTR,
	PMC,
	TR,
	XCR,
	MSR,
	MSW,
	CRn,
	DRn,
	CR0,
	DR0,
	DR1,
	DR2,
	DR3,
	DR4,
	DR5,
	DR6,
	DR7,
	IA32_TIMESTAMP_COUNTER,
	IA32_SYS,
	IA32_BIOS
};


static std::vector<disa_opinfo> disa_optable = { };

// it was either: parse everything into this table from an external file
// or, blow up your executable with ~20mb of assembly code
// by hard-coding the opcode information...
//Sorry guys.. I went with the latter
bool disa_load()
{
	disa_optable = 
	{
		{ "00", "add", { r_m8, r8 },					"Add" },
		{ "01", "add", { r_m16_32, r16_32 },			"Add" },
		{ "02", "add", { r8, r_m8 },					"Add" },
		{ "03", "add", { r16_32, r_m16_32 },			"Add" },
		{ "04", "add", { AL, imm8 },					"Add" },
		{ "05", "add", { EAX, imm16_32 },				"Add" },
		{ "06", "push", { ES },							"Push Extra Segment onto the stack" },
		{ "07", "pop", { ES },							"Pop Extra Segment off of the stack" },
		{ "08", "or", { r_m8, r8 },						"Logical Inclusive OR" },
		{ "09", "or", { r_m16_32, r16_32 },				"Logical Inclusive OR" },
		{ "0A", "or", { r8, r_m8 },						"Logical Inclusive OR" },
		{ "0B", "or", { r16_32, r_m16_32 },				"Logical Inclusive OR" },
		{ "0C", "or", { AL, imm8 },						"Logical Inclusive OR" },
		{ "0D", "or", { EAX, imm16_32 },				"Logical Inclusive OR" },
		{ "0E", "push", { CS },							"Push Code Segment onto the stack" },
		{ "0F+00+m0", "sldt", { r_m16_32 },				"Store Local Descriptor Table Register" },
		{ "0F+00+m1", "str", { r_m16 },					"Store Task Register" },
		{ "0F+00+m2", "lldt", { r_m16 },				"Load Local Descriptor Table Register" },
		{ "0F+00+m3", "ltr", { r_m16 },					"Load Task Register" },
		{ "0F+00+m4", "verr", { r_m16 },				"Verify a Segment for Reading" },
		{ "0F+00+m5", "verw", { r_m16 },				"Verify a Segment for Writing" },
		{ "0F+01+C1", "vmcall", {  },					"Call to VM Monitor" },
		{ "0F+01+C2", "vmlaunch", {  },					"Launch Virtual Machine" },
		{ "0F+01+C3", "vmresume", {  },					"Resume Virtual Machine" },
		{ "0F+01+C4", "vmxoff", {  },					"Leave VMX Operation" },
		{ "0F+01+C8", "monitor", {  },					"Set Up Monitor Address" },
		{ "0F+01+C9", "mwait", {  },					"Monitor Wait" },
		{ "0F+01+CA", "clac", {  },						"Clear AC flag in EFLAGS register" },
		{ "0F+01+m0", "sgdt", { r_m16_32 },				"Store Global Descriptor Table Register" },
		{ "0F+01+m1", "sidt", { r_m16_32 },				"Store Interrupt Descriptor Table Register" },
		{ "0F+01+m2", "lgdt", { r_m16_32 },				"Load Global Descriptor Table Register" },
		{ "0F+01+m3", "lidt", { r_m16_32 },				"Load Interrupt Descriptor Table Register" },
		{ "0F+01+m4", "smsw", { r_m16_32 },				"Store Machine Status Word" },
		{ "0F+01+m5", "smsw", { r_m16_32 },				"Store Machine Status Word" },
		{ "0F+01+m6", "lmsw", { r_m16_32 },				"Load Machine Status Word" },
		{ "0F+01+m7", "invplg", { r_m16_32 },			"Invalidate TLB Entry" },
		{ "0F+02", "lar", { r16_32, m16 },				"Load Access Rights Byte" }, // possibly m8 or m16_32 ..
		{ "0F+03", "lsl", { r16_32, m16 },				"Load Segment Limit" },  // possibly m8 or m16_32 ..
		{ "0F+04", "ud", {  },							"Undefined Instruction" },
		{ "0F+05", "syscall", {  },						"Fast System Call" },
		{ "0F+06", "clts", { CR0 },						"Clear Task-Switched Flag in CR0" },
		{ "0F+07", "sysret", {  },						"Return form fast system call" },
		{ "0F+08", "invd", {  },						"Invalidate Internal Caches" },
		{ "0F+09", "wbinvd", {  },						"Write Back and Invalidate Cache" },
		{ "0F+0B", "ud2", {  },							"Undefined Instruction" },
		{ "0F+0D", "nop", { r_m16_32 },					"No Operation" },
		{ "0F+10", "movups", { xmm, xmm_m128 },			"Move Unaligned Packed Single-FP Values" },
		{ "F3+0F+10", "movss", { xmm, xmm_m32 },		"Move Scalar Single-FP Values" },
		{ "66+0F+10", "movupd", { xmm, xmm_m128 },		"Move Unaligned Packed Double-FP Value" },
		{ "F2+0F+10", "movsd", { xmm, xmm_m64 },		"Move Scalar Double-FP Value" },
		{ "0F+11", "movups", { xmm_m128, xmm },			"Move Unaligned Packed Single-FP Values" },
		{ "F3+0F+11", "movss", { xmm_m32, xmm },		"Move Scalar Single-FP Values" },
		{ "66+0F+11", "movupd", { xmm_m128, xmm },		"Move Unaligned Packed Double-FP Value" },
		{ "F2+0F+11", "movsd", { xmm_m64, xmm },		"Move Scalar Double-FP Value" },
		{ "0F+12", "movhlps", { xmm, xmm },				"Move Packed Single-FP Values High to Low" },
		{ "0F+12", "movlps", { xmm, m64 },				"Move Low Packed Single-FP Values" },
		{ "F3+0F+12", "movlpd", { xmm, m64 },			"Move Low Packed Double-FP Value" },
		{ "66+0F+12", "movddup", { xmm, xmm_m64 },		"Move One Double-FP and Duplicate" },
		{ "F2+0F+12", "movsldup", { xmm, xmm_m64 },		"Move Packed Single-FP Low and Duplicate" },
		{ "0F+13", "movlps", { m64, xmm },				"Move Low Packed Single-FP Values" },
		{ "66+0F+13", "movlpd", { m64, xmm },			"Move Low Packed Double-FP Value" },
		{ "0F+14", "unpcklps", { xmm, xmm_m64 },		"Unpack and Interleave Low Packed Single-FP Values" },
		{ "66+0F+14", "unpcklpd", { xmm, xmm_m128 },	"Unpack and Interleave Low Packed Double-FP Values" },
		{ "0F+15", "unpckhps", { xmm, xmm_m64 },		"Unpack and Interleave High Packed Single-FP Values" },
		{ "66+0F+15", "unpckhpd", { xmm, xmm_m128 },	"Unpack and Interleave High Packed Double-FP Values" },
		{ "0F+16", "movlhps", { xmm, xmm },				"Move Packed Single-FP Values Low to High" },
		{ "0F+16", "movhps", { xmm, m64 },				"Move High Packed Single-FP Values" },
		{ "66+0F+16", "movhpd", { xmm, m64 },			"Move High Packed Double-FP Value" },
		{ "F3+0F+16", "movshdup", { xmm, xmm_m64 },		"Move Packed Single-FP High and Duplicate" },
		{ "0F+17", "movhps", { m64, xmm },				"Move High Packed Single-FP Values" },
		{ "66+0F+17", "movhpd", { m64, xmm },			"Move High Packed Double-FP Value" },
		{ "0F+18+m0", "prefetchnta", { m8 },			"Prefetch Data Into Caches" },
		{ "0F+18+m1", "prefetcht0", { m8 },				"Prefetch Data Into Caches" },
		{ "0F+18+m2", "prefetcht1", { m8 },				"Prefetch Data Into Caches" },
		{ "0F+18+m3", "prefetcht2", { m8 },				"Prefetch Data Into Caches" },
		{ "0F+18+m4", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+18+m5", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+18+m6", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+18+m7", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+19", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+1A", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+1B", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+1C", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+1D", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+1E", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+1F+m0", "nop", { r_m16_32 },				"No Operation" },
		{ "0F+1F+m1", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+1F+m2", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+1F+m3", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+1F+m4", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+1F+m5", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+1F+m6", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+1F+m7", "hint_nop", { r_m16_32 },			"Hintable NOP" },
		{ "0F+20", "mov", { r_m32, CRn },				"Move to/from Control Registers" },
		{ "0F+21", "mov", { r_m32, DRn },				"Move to/from Debug Registers" },
		{ "0F+22", "mov", { CRn, r_m32 },				"Move to/from Control Registers" },
		{ "0F+23", "mov", { DRn, r_m32,  },				"Move to/from Debug Registers" },
		{ "0F+28", "movaps", { xmm, xmm_m128,  },		"Move Aligned Packed Single-FP Values" },
		{ "66+0F+28", "movapd", { xmm, xmm_m128,  },	"Move Aligned Packed Double-FP Values" },
		{ "0F+29", "movaps", { xmm_m128, xmm,  },		"Move Aligned Packed Single-FP Values" },
		{ "66+0F+29", "movapd", { xmm_m128, xmm,  },	"Move Aligned Packed Double-FP Values" },
		{ "0F+2A", "cvtpi2ps", { xmm, mm_m64 },			"Convert Packed DW Integers to Single-FP Values" },
		{ "F3+0F+2A", "cvtpi2ss", { xmm, r_m32 },		"Convert DW Integer to Scalar Single-FP Value" },
		{ "66+0F+2A", "cvtpi2pd", { xmm, mm_m64 },		"Convert Packed DW Integers to Double-FP Values" },
		{ "F2+0F+2A", "cvtpi2sd", { xmm, r_m32 },		"Convert DW Integer to Scalar Double-FP Value" },
		{ "0F+2B", "movntps", { m128, xmm },			"Store Packed Single-FP Values Using Non-Temporal Hint" },
		{ "66+0F+2B", "movntpd", { m128, xmm },			"Store Packed Double-FP Values Using Non-Temporal Hint" },
		{ "0F+2C", "cvttps2pi", { mm, xmm_m64 },		"Convert with Trunc. Packed Single-FP Values to DW Integers" },
		{ "F3+0F+2C", "cvttss2si", { r32, xmm_m32 },	"Convert with Trunc. Scalar Single-FP Value to DW Integer" },
		{ "66+0F+2C", "cvttpd2pi", { mm, xmm_m128 },	"Convert with Trunc. Packed Double-FP Values to DW Integers" },
		{ "F2+0F+2C", "cvttsd2si", { r32, xmm_m64 },	"Convert with Trunc. Scalar Double-FP Value to Signed DW Int" },
		{ "0F+2D", "cvtps2pi", { mm, xmm_m64 },			"Convert Packed Single-FP Values to DW Integers" },
		{ "F3+0F+2D", "cvtss2si", { r32, xmm_m32 },		"Convert Scalar Single-FP Value to DW Integer" },
		{ "66+0F+2D", "cvtpd2pi", { mm, xmm_m128 },		"Convert Packed Double-FP Values to DW Integers" },
		{ "F2+0F+2D", "cvtsd2si", { r32, xmm_m64 },		"Convert Scalar Double-FP Value to DW Integer" },
		{ "0F+2E", "ucomiss", { xmm, xmm_m32 },			"Unordered Compare Scalar Ordered Single-FP Values and Set EFLAGS" },
		{ "66+0F+2E", "ucomisd", { xmm, xmm_m64 },		"Unordered Compare Scalar Ordered Double-FP Values and Set EFLAGS" },
		{ "0F+2F", "comiss", { xmm, xmm_m32 },			"Compare Scalar Ordered Single-FP Values and Set EFLAGS" },
		{ "66+0F+2F", "comisd", { xmm, xmm_m64 },		"Compare Scalar Ordered Double-FP Values and Set EFLAGS" },
		{ "0F+30", "wrmsr", {  },						"Write to Model Specific Register" },
		{ "0F+31", "rdtsc", {  },						"Read Time-Stamp Counter" },
		{ "0F+32", "rdmsr", {  },						"Read from Model Specific Register" },
		{ "0F+33", "rdpmc", {  },						"Read Performance-Monitoring Counters" },
		{ "0F+34", "sysenter", {  },					"Fast System Call" },
		{ "0F+35", "sysexit", {  },						"Fast Return from Fast System Call" },
		{ "0F+37", "getsec", {  },						"GETSEC Leaf Functions" },
		{ "0F+38+00", "pshufb", { mm, mm_m64 },			"Packed Shuffle Bytes" },
		{ "66+0F+38+00", "pshufb", { xmm, xmm_m128 },	"Packed Shuffle Bytes" },
		{ "0F+38+01", "phaddw", { mm, mm_m64 },			"Packed Horizontal Add" },
		{ "66+0F+38+01", "phaddw", { xmm, xmm_m128 },	"Packed Horizontal Add" },
		{ "0F+38+02", "phaddd", { mm, mm_m64 },			"Packed Horizontal Add" },
		{ "66+0F+38+02", "phaddd", { xmm, xmm_m128 },	"Packed Horizontal Add" },
		{ "0F+38+03", "phaddsw", { mm, mm_m64 },		"Packed Horizontal Add and Saturate" },
		{ "66+0F+38+03", "phaddsw", { xmm, xmm_m128 },	"Packed Horizontal Add and Saturate" },
		{ "0F+38+04", "pmaddubsw", { mm, mm_m64 },		"Multiply and Add Packed Signed and Unsigned Bytes" },
		{ "66+0F+38+04", "pmaddubsw", { xmm, xmm_m128 },"Multiply and Add Packed Signed and Unsigned Bytes" },
		{ "0F+38+05", "phsubw", { mm, mm_m64 },			"Packed Horizontal Subtract" },
		{ "66+0F+38+05", "phsubw", { xmm, xmm_m128 },	"Packed Horizontal Subtract" },
		{ "0F+38+06", "phsubd", { mm, mm_m64 },			"Packed Horizontal Subtract" },
		{ "66+0F+38+06", "phsubd", { xmm, xmm_m128 },	"Packed Horizontal Subtract" },
		{ "0F+38+07", "phsubsw", { mm, mm_m64 },		"Packed Horizontal Subtract and Saturate" },
		{ "66+0F+38+07", "phsubsw", { xmm, xmm_m128 },	"Packed Horizontal Subtract and Saturate" },
		{ "0F+38+08", "psignb", { mm, mm_m64 },			"Packed SIGN" },
		{ "66+0F+38+08", "psignb", { xmm, xmm_m128 },	"Packed SIGN" },
		{ "0F+38+09", "psignw", { mm, mm_m64 },			"Packed SIGN" },
		{ "66+0F+38+09", "psignw", { xmm, xmm_m128 },	"Packed SIGN" },
		{ "0F+38+0A", "psignd", { mm, mm_m64 },			"Packed SIGN" },
		{ "66+0F+38+0A", "psignd", { xmm, xmm_m128 },	"Packed SIGN" },
		{ "0F+38+0B", "pmulhrsw", { mm, mm_m64 },		"Packed Multiply High with Round and Scale" },
		{ "66+0F+38+0B", "pmulhrsw", { xmm, xmm_m128 },	"Packed Multiply High with Round and Scale" },
		{ "66+0F+38+10", "pblendvb",{xmm,xmm_m128,xmm0},"Variable Blend Packed Bytes" },
		{ "66+0F+38+14", "blendvps",{xmm,xmm_m128,xmm0},"Variable Blend Packed Single-FP Values" },
		{ "66+0F+38+15", "blendvpd",{xmm,xmm_m128,xmm0},"Variable Blend Packed Double-FP Values" },
		{ "66+0F+38+17", "ptest",{ xmm, xmm_m128 },		"Logical Compare" },
		{ "0F+38+1C", "pabsb", { mm, mm_m64 },			"Packed Absolute Value" },
		{ "66+0F+38+1C", "pabsb", { xmm, xmm_m128 },	"Packed Absolute Value" },
		{ "0F+38+1D", "pabsw", { mm, mm_m64 },			"Packed Absolute Value" },
		{ "66+0F+38+1D", "pabsw", { xmm, xmm_m128 },	"Packed Absolute Value" },
		{ "0F+38+1E", "pabsd", { mm, mm_m64 },			"Packed Absolute Value" },
		{ "66+0F+38+1E", "pabsd", { xmm, xmm_m128 },	"Packed Absolute Value" },
		{ "66+0F+38+20", "pmovsxbw", { xmm, m64 },		"Packed Move with Sign Extend" },
		{ "66+0F+38+21", "pmovsxbd", { xmm, m32 },		"Packed Move with Sign Extend" },
		{ "66+0F+38+22", "pmovsxbq", { xmm, m16 },		"Packed Move with Sign Extend" },
		{ "66+0F+38+23", "pmovsxbd", { xmm, m64 },		"Packed Move with Sign Extend" },
		{ "66+0F+38+24", "pmovsxbq", { xmm, m32 },		"Packed Move with Sign Extend" },
		{ "66+0F+38+25", "pmovsxdq", { xmm, m64 },		"Packed Move with Sign Extend" },
		{ "66+0F+38+28", "pmuldq", { xmm, xmm_m128 },	"Multiply Packed Signed Dword Integers" },
		{ "66+0F+38+29", "pcmpeqq", { xmm, xmm_m128 },	"Compare Packed Qword Data for Equal" },
		{ "66+0F+38+2A", "movntdqa", { xmm, m128 },		"Load Double Quadword Non-Temporal Aligned Hint" },
		{ "66+0F+38+2B", "packusdw", { xmm, xmm_m128 },	"Pack with Unsigned Saturation" },
		{ "66+0F+38+30", "pmovzxbw", { xmm, m64 },		"Packed Move with Zero Extend" },
		{ "66+0F+38+31", "pmovzxbd", { xmm, m32 },		"Packed Move with Zero Extend" },
		{ "66+0F+38+32", "pmovzxbq", { xmm, m16 },		"Packed Move with Zero Extend" },
		{ "66+0F+38+33", "pmovzxbd", { xmm, m64 },		"Packed Move with Zero Extend" },
		{ "66+0F+38+34", "pmovzxbq", { xmm, m32 },		"Packed Move with Zero Extend" },
		{ "66+0F+38+35", "pmovzxbq", { xmm, m64 },		"Packed Move with Zero Extend" },
		{ "66+0F+38+37", "pcmpgtq", { xmm, xmm_m128 },	"Compare Packed Qword Data for Greater Than" },
		{ "66+0F+38+38", "pminsb", { xmm, xmm_m128 },	"Minimum of Packed Signed Byte Integers" },
		{ "66+0F+38+39", "pminsd", { xmm, xmm_m128 },	"Minimum of Packed Signed Dword Integers" },
		{ "66+0F+38+3A", "pminuw", { xmm, xmm_m128 },	"Minimum of Packed Unsigned Word Integers" },
		{ "66+0F+38+3B", "pminud", { xmm, xmm_m128 },	"Minimum of Packed Unsigned Dword Integers" },
		{ "66+0F+38+3C", "pmaxsb", { xmm, xmm_m128 },	"Maximum of Packed Signed Byte Integers" },
		{ "66+0F+38+3D", "pmaxsd", { xmm, xmm_m128 },	"Maximum of Packed Signed Dword Integers" },
		{ "66+0F+38+3E", "pmaxuw", { xmm, xmm_m128 },	"Maximum of Packed Unsigned Word Integers" },
		{ "66+0F+38+3F", "pmaxud", { xmm, xmm_m128 },	"Maximum of Packed Unsigned Dword Integers" },
		{ "66+0F+38+40", "pmulld", { xmm, xmm_m128 },	"Multiply Packed Signed Dword Integers and Store Low Result" },
		{ "66+0F+38+41", "phminposuw",{ xmm, xmm_m128 },"Packed Horizontal Word Minimum" },
		{ "66+0F+38+80", "invept", { r32, m128 },		"Invalidate Translations Derived from EPT" },
		{ "66+0F+38+81", "invvpid", { r32, m128 },		"Invalidate Translations Based on VPID" },
		{ "0F+38+F0", "movbe", { r16_32, m16_32 },		"Move Data After Swapping Bytes" },
		{ "F2+0F+38+F0", "crc32", { r32, r_m8 },		"Accumulate CRC32 Value" },
		{ "0F+38+F1", "movbe", { m16_32, r16_32 },		"Move Data After Swapping Bytes" },
		{ "F2+0F+38+F1", "crc32", { r32, r_m16_32 },	"Accumulate CRC32 Value" },
		{ "66+0F+3A+08","roundps",{ xmm,xmm_m128,imm8 },"Round Packed Single-FP Values" },
		{ "66+0F+3A+09","roundpd",{ xmm,xmm_m128,imm8 },"Round Packed Double-FP Values" },
		{ "66+0F+3A+0A", "roundss",{ xmm,xmm_m32,imm8 },"Round Scalar Single-FP Values" },
		{ "66+0F+3A+0B", "roundsd",{ xmm,xmm_m64,imm8 },"Round Scalar Double-FP Values" },
		{ "66+0F+3A+0C","blendps",{ xmm,xmm_m128,imm8 },"Round Packed Single-FP Values" },
		{ "66+0F+3A+0D","blendpd",{ xmm,xmm_m128,imm8 },"Round Packed Double-FP Values" },
		{ "66+0F+3A+0E","pblendw",{ xmm,xmm_m128,imm8 },"Blend Packed Words" },
		{ "0F+3A+0F", "palignr", { mm, mm_m64 },		"Packed Align Right" },
		{ "66+0F+3A+0F", "palignr", { mm, xmm_m128 },	"Packed Align Right" },
		{ "66+0F+3A+14", "pextrb", { m8, xmm, imm8 },	"Extract Byte" },
		{ "66+0F+3A+15", "pextrw", { m16, xmm, imm8 },	"Extract Word" },
		{ "66+0F+3A+16", "pextrd", { m32, xmm, imm8 },	"Extract Dword/Qword" },
		{ "66+0F+3A+17", "extractps",{ m64, xmm, imm8 },"Extract Packed Single-FP Value" },
		{ "66+0F+3A+20", "pinsrb", { xmm, m8, imm8 },	"Insert Byte" },
		{ "66+0F+3A+21", "insertps", { xmm, m32, imm8 },"Insert Packed Single-FP Value" },
		{ "66+0F+3A+22", "pinsrd", { xmm, m64, imm8 },	"Insert Dword/Qword" },
		{ "66+0F+3A+40", "dpps", { xmm, xmm_m128 },		"Dot Product of Packed Single-FP Values" },
		{ "66+0F+3A+41", "dppd", { xmm, xmm_m128 },		"Dot Product of Packed Double-FP Values" },
		{ "66+0F+3A+42","mpsadbw",{xmm, xmm_m128, imm8},"Compute Multiple Packed Sums of Absolute Difference" },
		{ "66+0F+3A+60","pcmpestrm",{xmm0,xmm,xmm_m128},"Packed Compare Explicit Length Strings, Return Mask" },
		{ "66+0F+3A+61","pcmpestri",{ECX,xmm,xmm_m128},	"Packed Compare Explicit Length Strings, Return Index" },
		{ "66+0F+3A+62","pcmpistrm",{xmm0,xmm,xmm_m128,imm8},"Packed Compare Implicit Length Strings, Return Mask" },
		{ "66+0F+3A+63","pcmpistri",{ECX,xmm,xmm_m128, imm8},"Packed Compare Implicit Length Strings, Return Index" },
		{ "0F+40", "cmovo", { r16_32, r_m16_32 },		"Conditional Move - overflow (OF=1)" },
		{ "0F+41", "cmovno", { r16_32, r_m16_32 },		"Conditional Move - not overflow (OF=0)" },
		{ "0F+42", "cmovb", { r16_32, r_m16_32 },		"Conditional Move - below/not above or equal/carry (CF=1)" },
		{ "0F+43", "cmovnb", { r16_32, r_m16_32 },		"Conditional Move - onot below/above or equal/not carry (CF=0)" },
		{ "0F+44", "cmove", { r16_32, r_m16_32 },		"Conditional Move - zero/equal (ZF=1)" },
		{ "0F+45", "cmovne", { r16_32, r_m16_32 },		"Conditional Move - not zero/not equal (ZF=0)" },
		{ "0F+46", "cmovbe", { r16_32, r_m16_32 },		"Conditional Move - below or equal/not above (CF=1 OR ZF=1)" },
		{ "0F+47", "cmova", { r16_32, r_m16_32 },		"Conditional Move - not below or equal/above (CF=0 AND ZF=0)" },
		{ "0F+48", "cmovs", { r16_32, r_m16_32 },		"Conditional Move - sign (SF=1)" },
		{ "0F+49", "cmovns", { r16_32, r_m16_32 },		"Conditional Move - not sign (SF=0)" },
		{ "0F+4A", "cmovp", { r16_32, r_m16_32 },		"Conditional Move - parity/parity even (PF=1)" },
		{ "0F+4B", "cmovnp", { r16_32, r_m16_32 },		"Conditional Move - not parity/parity odd (PF=0)" },
		{ "0F+4C", "cmovl", { r16_32, r_m16_32 },		"Conditional Move - less/not greater (SF!=OF)" },
		{ "0F+4D", "cmovge", { r16_32, r_m16_32 },		"Conditional Move - not less/greater or equal (SF=OF)" },
		{ "0F+4E", "cmovng", { r16_32, r_m16_32 },		"Conditional Move - less or equal/not greater ((ZF=1) OR (SF!=OF))" },
		{ "0F+4F", "cmovg", { r16_32, r_m16_32 },		"Conditional Move - not less nor equal/greater ((ZF=0) AND (SF=OF))" },
		{ "0F+50", "movmskps", { r32, xmm },			"Extract Packed Single-FP Sign Mask" },
		{ "66+0F+50", "movmskpd", { r32, xmm },			"Extract Packed Double-FP Sign Mask" },
		{ "66+0F+50", "movmskpd", { r32, xmm },			"Extract Packed Double-FP Sign Mask" },
		{ "0F+51", "sqrtps", { xmm, xmm_m128 },			"Compute Square Roots of Packed Single-FP Values" },
		{ "F3+0F+51", "sqrtss", { xmm, xmm_m32 },		"Compute Square Root of Scalar Single-FP Value" },
		{ "66+0F+51", "sqrtpd", { xmm, xmm_m128 },		"Compute Square Roots of Packed Double-FP Values" },
		{ "F2+0F+51", "sqrtsd", { xmm, xmm_m64 },		"Compute Square Root of Scalar Double-FP Value" },
		{ "0F+52", "rsqrtps", { xmm, xmm_m128 },		"Compute Recipr. of Square Roots of Packed Single-FP Values" },
		{ "F3+0F+52", "rsqrtss", { xmm, xmm_m32 },		"Compute Recipr. of Square Root of Scalar Single-FP Value" },
		{ "0F+53", "rcpps", { xmm, xmm_m128 },			"Compute Reciprocals of Packed Single-FP Values" },
		{ "F3+0F+53", "rcpss", { xmm, xmm_m32 },		"Compute Reciprocal of Scalar Single-FP Values" },
		{ "0F+54", "andps", { xmm, xmm_m128 },			"Bitwise Logical AND of Packed Single-FP Values" },
		{ "66+0F+54", "andpd", { xmm, xmm_m128 },		"Bitwise Logical AND of Packed Double-FP Values" },
		{ "0F+55", "andnps", { xmm, xmm_m128 },			"Bitwise Logical AND NOT of Packed Single-FP Values" },
		{ "66+0F+55", "andnpd", { xmm, xmm_m128 },		"Bitwise Logical AND NOT of Packed Double-FP Values" },
		{ "0F+56", "orps", { xmm, xmm_m128 },			"Bitwise Logical OR of Packed Single-FP Values" },
		{ "66+0F+56", "orpd", { xmm, xmm_m128 },		"Bitwise Logical OR of Packed Double-FP Values" },
		{ "0F+57", "xorps", { xmm, xmm_m128 },			"Bitwise Logical XOR of Packed Single-FP Values" },
		{ "66+0F+57", "xorpd", { xmm, xmm_m128 },		"Bitwise Logical XOR of Packed Double-FP Values" },
		{ "0F+58", "addps", { xmm, xmm_m128 },			"Add Packed Single-FP Values" },
		{ "F3+0F+58", "addss", { xmm, xmm_m32 },		"Add Scalar Single-FP Values" },
		{ "66+0F+58", "addpd", { xmm, xmm_m128 },		"Add Packed Double-FP Values" },
		{ "F2+0F+58", "addsd", { xmm, xmm_m64 },		"Add Scalar Double-FP Values" },
		{ "0F+59", "mulps", { xmm, xmm_m128 },			"Multiply Packed Single-FP Values" },
		{ "F3+0F+59", "mulss", { xmm, xmm_m32 },		"Multiply Scalar Single-FP Value" },
		{ "66+0F+59", "mulpd", { xmm, xmm_m128 },		"Multiply Packed Double-FP Values" },
		{ "F2+0F+59", "addsd", { xmm, xmm_m64 },		"Multiply Scalar Double-FP Values" },
		{ "0F+5A", "cvtps2pd", { xmm, xmm_m128 },		"Convert Packed Single-FP Values to Double-FP Values" },
		{ "F3+0F+5A", "cvtpd2ps", { xmm, xmm_m128 },	"Convert Packed Double-FP Values to Single-FP Values" },
		{ "66+0F+5A", "cvtss2sd", { xmm, xmm_m32 },		"Convert Scalar Single-FP Value to Scalar Double-FP Value" },
		{ "F2+0F+5A", "cvtsd2ss", { xmm, xmm_m64 },		"Convert Scalar Double-FP Value to Scalar Single-FP Value" },
		{ "0F+5B", "cvtdq2ps", { xmm, xmm_m128 },		"Convert Packed DW Integers to Single-FP Values" },
		{ "66+0F+5B", "cvtps2dq", { xmm, xmm_m128 },	"Convert Packed Single-FP Values to DW Integers" },
		{ "F3+0F+5B", "cvttps2dq", { xmm, xmm_m128 },	"Convert with Trunc. Packed Single-FP Values to DW Integers" },
		{ "0F+5C", "subps", { xmm, xmm_m128 },			"Subtract Packed Single-FP Values" },
		{ "F3+0F+5C", "subss", { xmm, xmm_m32 },		"Subtract Scalar Single-FP Values" },
		{ "66+0F+5C", "subpd", { xmm, xmm_m128 },		"Subtract Packed Double-FP Values" },
		{ "F2+0F+5C", "subsd", { xmm, xmm_m64 },		"Subtract Scalar Double-FP Values" },
		{ "0F+5D", "minps", { xmm, xmm_m128 },			"Return Minimum Packed Single-FP Values" },
		{ "F3+0F+5D", "minss", { xmm, xmm_m32 },		"Return Minimum Scalar Single-FP Values" },
		{ "66+0F+5D", "minpd", { xmm, xmm_m128 },		"Return Minimum Packed Double-FP Values" },
		{ "F2+0F+5D", "minsd", { xmm, xmm_m64 },		"Return Minimum Scalar Double-FP Values" },
		{ "0F+5E", "divps", { xmm, xmm_m128 },			"Divide Packed Single-FP Values" },
		{ "F3+0F+5E", "divss", { xmm, xmm_m32 },		"Divide Scalar Single-FP Values" },
		{ "66+0F+5E", "divpd", { xmm, xmm_m128 },		"Divide Packed Double-FP Values" },
		{ "F2+0F+5E", "divsd", { xmm, xmm_m64 },		"Divide Scalar Double-FP Values" },
		{ "0F+5F", "maxps", { xmm, xmm_m128 },			"Return Maximum Packed Single-FP Values" },
		{ "F3+0F+5F", "maxss", { xmm, xmm_m32 },		"Return Maximum Scalar Single-FP Values" },
		{ "66+0F+5F", "maxpd", { xmm, xmm_m128 },		"Return Maximum Packed Double-FP Values" },
		{ "F2+0F+5F", "maxsd", { xmm, xmm_m64 },		"Return Maximum Scalar Double-FP Values" },
		{ "0F+60", "punpcklbw", { mm, mm_m64 },			"Unpack Low Data" },
		{ "66+0F+60", "punpcklbw", { xmm, xmm_m128 },	"Unpack Low Data" },
		{ "0F+61", "punpcklbd", { mm, mm_m64 },			"Unpack Low Data" },
		{ "66+0F+61", "punpcklbd", { xmm, xmm_m128 },	"Unpack Low Data" },
		{ "0F+62", "punpcklbq", { mm, mm_m64 },			"Unpack Low Data" },
		{ "66+0F+62", "punpcklbq", { xmm, xmm_m128 },	"Unpack Low Data" },
		{ "0F+63", "packsswb", { mm, mm_m64 },			"Pack with Signed Saturation" },
		{ "66+0F+63", "packsswb", { xmm, xmm_m128 },	"Pack with Signed Saturation" },
		{ "0F+64", "pcmpgtb", { mm, mm_m64 },			"Compare Packed Signed Integers for Greater Than" },
		{ "66+0F+64", "pcmpgtb", { xmm, xmm_m128 },		"Compare Packed Signed Integers for Greater Than" },
		{ "0F+65", "pcmpgtw", { mm, mm_m64 },			"Compare Packed Signed Integers for Greater Than" },
		{ "66+0F+65", "pcmpgtw", { xmm, xmm_m128 },		"Compare Packed Signed Integers for Greater Than" },
		{ "0F+66", "pcmpgtd", { mm, mm_m64 },			"Compare Packed Signed Integers for Greater Than" },
		{ "66+0F+66", "pcmpgtd", { xmm, xmm_m128 },		"Compare Packed Signed Integers for Greater Than" },
		{ "0F+67", "packuswb", { mm, mm_m64 },			"Pack with Unsigned Saturation" },
		{ "66+0F+67", "packuswb", { xmm, xmm_m128 },	"Pack with Unsigned Saturation" },
		{ "0F+68", "punpckhbw", { mm, mm_m64 },			"Unpack High Data" },
		{ "66+0F+68", "punpckhbw", { xmm, xmm_m128 },	"Unpack High Data" },
		{ "0F+69", "punpckhwd", { mm, mm_m64 },			"Unpack High Data" },
		{ "66+0F+69", "punpckhwd", { xmm, xmm_m128 },	"Unpack High Data" },
		{ "0F+6A", "punpckhdq", { mm, mm_m64 },			"Unpack High Data" },
		{ "66+0F+6A", "punpckhdq", { xmm, xmm_m128 },	"Unpack High Data" },
		{ "0F+6B", "packssdw", { mm, mm_m64 },			"Pack with Signed Saturation" },
		{ "66+0F+6B", "packssdw", { xmm, xmm_m128 },	"Pack with Signed Saturation" },
		{ "66+0F+6C", "punpcklqdq", { xmm, xmm_m128 },	"Unpack Low Data" },
		{ "66+0F+6D", "punpckhqdq", { xmm, xmm_m128 },	"Unpack High Data" },
		{ "0F+6E", "movd", { xmm, r_m32 },				"Move Doubleword" },
		{ "66+0F+6E", "movd", { xmm, r_m32 },			"Move Doubleword" },
		{ "0F+6F", "movq", { xmm, mm_m64 },				"Move Quadword" },
		{ "66+0F+6F", "movdqa", { xmm, xmm_m128 },		"Move Aligned Double Quadword" },
		{ "F3+0F+6F", "movdqu", { xmm, xmm_m128 },		"Move Unaligned Double Quadword" },
		{ "0F+70", "pshufw", { mm_m64, imm8 },			"Shuffle Packed Words" },
		{ "F3+0F+70", "pshuflw", { xmm_m128, imm8 },	"Shuffle Packed Low Words" },
		{ "66+0F+70", "pshufhw", { xmm_m128, imm8 },	"Shuffle Packed High Words" },
		{ "F2+0F+70", "pshufd", { xmm_m128, imm8 },		"Shuffle Packed Doublewords" },
		{ "0F+71+m2", "psrlw", { mm, imm8 },			"Shift Packed Data Right Logical" },
		{ "66+0F+71+m2", "psrlw", { xmm, imm8 },		"Shift Packed Data Right Logical" },
		{ "0F+71+m4", "psraw", { mm, imm8 },			"Shift Packed Data Right Arithmetic" },
		{ "66+0F+71+m4", "psraw", { xmm, imm8 },		"Shift Packed Data Right Arithmetic" },
		{ "0F+71+m6", "psllw", { mm, imm8 },			"Shift Packed Data Left Logical" },
		{ "66+0F+71+m6", "psllw", { xmm, imm8 },		"Shift Packed Data Left Logical" },
		{ "0F+72+m2", "psrld", { mm, imm8 },			"Shift Double Quadword Right Logical" },
		{ "66+0F+72+m2", "psrld", { xmm, imm8 },		"Shift Double Quadword Right Logical" },
		{ "0F+72+m4", "psrad", { mm, imm8 },			"Shift Packed Data Right Arithmetic" },
		{ "66+0F+72+m4", "psrad", { xmm, imm8 },		"Shift Packed Data Right Arithmetic" },
		{ "0F+72+m6", "pslld", { mm, imm8 },			"Shift Packed Data Left Logical" },
		{ "66+0F+72+m6", "pslld", { xmm, imm8 },		"Shift Packed Data Left Logical" },
		{ "0F+73+m2", "psrld", { mm, imm8 },			"Shift Packed Data Right Logical" },
		{ "66+0F+73+m2", "psrld", { xmm, imm8 },		"Shift Packed Data Right Logical" },
		{ "0F+73+m3", "psrad", { mm, imm8 },			"Shift Double Quadword Right Logical" },
		{ "66+0F+73+m6", "psrad", { xmm, imm8 },		"Shift Packed Data Left Logical" },
		{ "0F+73+m6", "pslld", { mm, imm8 },			"Shift Packed Data Left Logical" },
		{ "66+0F+73+m7", "pslld", { xmm, imm8 },		"Shift Double Quadword Left Logical" },
		{ "0F+74", "pcmpeqb", { mm, mm_m64 },			"Compare Packed Data for Equal" },
		{ "66+0F+74", "pcmpeqb", { xmm, xmm_m128 },		"Compare Packed Data for Equal" },
		{ "0F+75", "pcmpeqw", { mm, mm_m64 },			"Compare Packed Data for Equal" },
		{ "66+0F+75", "pcmpeqw", { xmm, xmm_m128 },		"Compare Packed Data for Equal" },
		{ "0F+76", "pcmpeqd", { mm, mm_m64 },			"Compare Packed Data for Equal" },
		{ "66+0F+76", "pcmpeqd", { xmm, xmm_m128 },		"Compare Packed Data for Equal" },
		{ "0F+77", "emms", {  },						"Empty MMX Technology State" },
		{ "0F+78", "vmread", {  },						"Read Field from Virtual-Machine Control Structure" },
		{ "0F+79", "vmwrite", {  },						"Write Field to Virtual-Machine Control Structure" },
		{ "66+0F+7C", "haddpd", { xmm, xmm_m128 },		"Packed Double-FP Horizontal Add" },
		{ "F2+0F+7C", "haddps", { xmm, xmm_m128 },		"Packed Single-FP Horizontal Add" },
		{ "66+0F+7D", "hsubpd", { xmm, xmm_m128 },		"Packed Double-FP Horizontal Subtract" },
		{ "F2+0F+7D", "hsubps", { xmm, xmm_m128 },		"Packed Single-FP Horizontal Subtract" },
		{ "0F+7E", "movd", { r_m32, mm },				"Move Doubleword" },
		{ "66+0F+7E", "movd", { r_m32, xmm },			"Move Doubleword" },
		{ "F3+0F+7E", "movq", { xmm, xmm_m64 },			"Move Quadword" },
		{ "0F+7F", "movq", { xmm_m64, mm },				"Move Quadword" },
		{ "66+0F+7F", "movdqa", { xmm_m128, xmm },		"Move Aligned Double Quadword" },
		{ "F3+0F+7F", "movdqu", { xmm_m128, xmm },		"Move Unaligned Double Quadword" },
		{ "0F+80", "long jo", { rel16_32 },				"Jump far if overflow (OF=1)" },
		{ "0F+81", "long jno", { rel16_32 },			"Jump far if not overflow (OF=0)" },
		{ "0F+82", "long jb", { rel16_32 },				"Jump far if below/not above or equal/carry (CF=1)" },
		{ "0F+83", "long jnb", { rel16_32 },			"Jump far if not below/above or equal/not carry (CF=0)" },
		{ "0F+84", "long je", { rel16_32 },				"Jump far if zero/equal (ZF=1)" },
		{ "0F+85", "long jne", { rel16_32 },			"Jump far if not zero/not equal (ZF=0)" },
		{ "0F+86", "long jna", { rel16_32 },			"Jump far if below or equal/not above (CF=1 OR ZF=1)" },
		{ "0F+87", "long ja", { rel16_32 },				"Jump far if not below or equal/above (CF=0 AND ZF=0)" },
		{ "0F+88", "long js", { rel16_32 },				"Jump far if sign (SF=1)" },
		{ "0F+89", "long jns", { rel16_32 },			"Jump far if not sign (SF=0)" },
		{ "0F+8A", "long jp", { rel16_32 },				"Jump far if parity/parity even (PF=1)" },
		{ "0F+8B", "long jnp", { rel16_32 },			"Jump far if not parity/parity odd (PF=0)" },
		{ "0F+8C", "long jl", { rel16_32 },				"Jump far if less/not greater (SF!=OF)" },
		{ "0F+8D", "long jnl", { rel16_32 },			"Jump far if not less/greater or equal (SF=OF)" },
		{ "0F+8E", "long jng", { rel16_32 },			"Jump far if less or equal/not greater ((ZF=1) OR (SF!=OF))" },
		{ "0F+8F", "long jg", { rel16_32 },				"Jump far if not less nor equal/greater ((ZF=0) AND (SF=OF))" },
		{ "0F+90", "seto", { r_m8 },					"Set Byte on Condition - overflow (OF=1)" },
		{ "0F+91", "setno", { r_m8 },					"Set Byte on Condition - not overflow (OF=0)" },
		{ "0F+92", "setb", { r_m8 },					"Set Byte on Condition - below/not above or equal/carry (CF=1)" },
		{ "0F+93", "setnb", { r_m8 },					"Set Byte on Condition - not below/above or equal/not carry (CF=0)" },
		{ "0F+94", "sete", { r_m8 },					"Set Byte on Condition - zero/equal (ZF=1)" },
		{ "0F+95", "setne", { r_m8 },					"Set Byte on Condition - not zero/not equal (ZF=0)" },
		{ "0F+96", "setna", { r_m8 },					"Set Byte on Condition - below or equal/not above (CF=1 OR ZF=1)" },
		{ "0F+97", "seta", { r_m8 },					"Set Byte on Condition - not below or equal/above (CF=0 AND ZF=0)" },
		{ "0F+98", "sets", { r_m8 },					"Set Byte on Condition - sign (SF=1)" },
		{ "0F+99", "setns", { r_m8 },					"Set Byte on Condition - not sign (SF=0)" },
		{ "0F+9A", "setp", { r_m8 },					"Set Byte on Condition - parity/parity even (PF=1)" },
		{ "0F+9B", "setnp", { r_m8 },					"Set Byte on Condition - not parity/parity odd (PF=0)" },
		{ "0F+9C", "setl", { r_m8 },					"Set Byte on Condition - less/not greater (SF!=OF)" },
		{ "0F+9D", "setnl", { r_m8 },					"Set Byte on Condition - not less/greater or equal (SF=OF)" },
		{ "0F+9E", "setng", { r_m8 },					"Set Byte on Condition - less or equal/not greater ((ZF=1) OR (SF!=OF))" },
		{ "0F+9F", "setg", { r_m8 },					"Set Byte on Condition - not less nor equal/greater ((ZF=0) AND (SF=OF))" },
		{ "0F+A0", "push", { FS },						"Push Word, Doubleword or Quadword Onto the Stack" },
		{ "0F+A1", "pop", { FS },						"Pop a Value from the Stack" },
		{ "0F+A2", "cpuid", { IA32_BIOS },				"CPU Identification" },
		{ "0F+A3", "bt", { r_m16_32, r16_32 },			"Bit Test" },
		{ "0F+A4", "shld", { r_m16_32, r16_32, imm8 },	"Double Precision Shift Left" },
		{ "0F+A5", "shld", { r_m16_32, r16_32, CL },	"Double Precision Shift Left" },
		{ "0F+A8", "push", { GS },						"Push Word, Doubleword or Quadword Onto the Stack" },
		{ "0F+A9", "pop", { GS },						"Pop a Value from the Stack" },
		{ "0F+AA", "rsm", {  },							"Resume from System Management Mode" },
		{ "0F+AB", "bts", { r_m16_32, r16_32 },			"Bit Test and Set" },
		{ "0F+AC", "shrd", { r_m16_32, r16_32, imm8 },	"Double Precision Shift Right" },
		{ "0F+AD", "shrd", { r_m16_32, r16_32, CL },	"Double Precision Shift Right" },
		{ "0F+AE+m0", "fxsave", { m512, ST, ST1 },		"Save x87 FPU, MMX, XMM, and MXCSR State" },
		{ "0F+AE+m1", "fxrstor", { ST, ST1, ST2 },		"Restore x87 FPU, MMX, XMM, and MXCSR State" },
		{ "0F+AE+m2", "ldmxcsr", { m32 },				"Load MXCSR Register" },
		{ "0F+AE+m3", "stmxcsr", { m32 },				"Store MXCSR Register State" },
		{ "0F+AE+m4", "xsave", { m, EDX, EAX },			"Save Processor Extended States" },
		{ "0F+AE+m5", "lfence", {  },					"Load Fence" },
		{ "0F+AE+m5", "xrstor", { ST, ST1, ST2 },		"Restore Processor Extended States" },
		{ "0F+AE+m6", "mfence", {  },					"Memory Fence" },
		{ "0F+AE+m7", "sfence", {  },					"Store Fence" },
		{ "0F+AE+m7", "clflush", { m8 },				"Flush Cache Line" },
		{ "0F+AF", "imul", { r16_32, r_m16_32 },		"Signed Multiply" },
		{ "0F+B0", "cmpxchg", { r_m8, AL, r8 },			"Compare and Exchange" },
		{ "0F+B1", "cmpxchg", { r_m16_32, EAX, r16_32 },"Compare and Exchange" },
		{ "0F+B2", "lss",{SS, r16_32, m16_32_and_16_32},"Load Far Pointer" },
		{ "0F+B3", "btr", { r_m16_32, r16_32 },			"Bit Test and Reset" },
		{ "0F+B4", "lfs",{FS,r_m16_32,m16_32_and_16_32},"Load Far Pointer" },
		{ "0F+B5", "lgs",{GS,r_m16_32,m16_32_and_16_32},"Load Far Pointer" },
		{ "0F+B6", "movzx", { r16_32, r_m8 },			"Move with Zero-Extend" },
		{ "0F+B7", "movzx", { r16_32, r_m16 },			"Move with Zero-Extend" },
		{ "F3+0F+B8", "popcnt", { r16_32, r_m16_32 },	"Bit Population Count" },
		{ "0F+B9", "ud", {  },							"Undefined Instruction" },
		{ "0F+BA+m4", "bt", { r_m16_32, imm8 },			"Bit Test" },
		{ "0F+BA+m5", "bts", { r_m16_32, imm8 },		"Bit Test and Set" },
		{ "0F+BA+m6", "btr", { r_m16_32, imm8 },		"Bit Test and Reset" },
		{ "0F+BA+m7", "btc", { r_m16_32, imm8 },		"Bit Test and Complement" },
		{ "0F+BB", "btc", { r_m16_32, r16_32 },			"Bit Test and Complement" },
		{ "0F+BC", "bsf", { r16_32, r_m16_32 },			"Bit Scan Forward" },
		{ "0F+BD", "bsr", { r16_32, r_m16_32 },			"Bit Scan Reverse" },
		{ "0F+BE", "movsx", { r16_32, r_m8 },			"Move with Sign-Extension" },
		{ "0F+BF", "movsx", { r16_32, r_m16 },			"Move with Sign-Extension" },
		{ "0F+C0", "xadd", { r_m8, r8 },				"Exchange and Add" },
		{ "0F+C1", "xadd", { r_m16_32, r16_32 },		"Exchange and Add" },
		{ "0F+C2", "cmpps", { xmm, xmm_m128, imm8 },	"Compare Packed Single-FP Values" },
		{ "F3+0F+C2", "cmpss", { xmm, xmm_m32, imm8 },	"Compare Scalar Single-FP Values" },
		{ "66+0F+C2", "cmppd", { xmm, xmm_m128, imm8 },	"Compare Packed Double-FP Values" },
		{ "F2+0F+C2", "cmpsd", { xmm, xmm_m64, imm8 },	"Compare Scalar Double-FP Values" },
		{ "0F+C3", "movnti", { m32, r32 },				"Store Doubleword Using Non-Temporal Hint" },
		{ "0F+C4", "pinsrw", { mm, m16, imm8 },			"Insert Word" },
		{ "66+0F+C4", "pinsrw", { xmm, m16, imm8 },		"Insert Word" },
		{ "0F+C5", "pextrw", { r32, mm, imm8 },			"Extract Word" },
		{ "66+0F+C5", "pextrw", { r32, xmm, imm8 },		"Extract Word" },
		{ "0F+C6", "shufps", { xmm, xmm_m128, imm8 },	"Shuffle Packed Single-FP Values" },
		{ "66+0F+C6", "shufpd", { xmm, xmm_m128, imm8 },"Shuffle Packed Double-FP Values" },
		{ "0F+C7+m1", "cmpxchg8b", { m64, EAX, EDX },	"Compare and Exchange Bytes" },
		{ "0F+C7+m6", "vmptrld", { m64 },				"Load Pointer to Virtual-Machine Control Structure" },
		{ "66+0F+C7+m6", "vmclean", { m64 },			"Clear Virtual-Machine Control Structure" },
		{ "F3+0F+C7+m6", "vmxon", { m64 },				"Enter VMX Operation" },
		{ "0F+C7+m7", "vmptrst", { m64 },				"Store Pointer to Virtual-Machine Control Structure" },
		{ "0F+C8+r", "bswap", { r16_32 },				"Byte Swap" },
		{ "66+0F+D0", "addsubpd", { xmm, xmm_m128 },	"Packed Double-FP Add/Subtract" },
		{ "F2+0F+D0", "addsubpd", { xmm, xmm_m128 },	"Packed Single-FP Add/Subtract" },
		{ "0F+D1", "psrlw", { mm, mm_m64 },				"Shift Packed Data Right Logical" },
		{ "66+0F+D1", "psrlw", { xmm, xmm_m128 },		"Shift Packed Data Right Logical" },
		{ "0F+D2", "psrld", { mm, mm_m64 },				"Shift Packed Data Right Logical" },
		{ "66+0F+D2", "psrld", { xmm, xmm_m128 },		"Shift Packed Data Right Logical" },
		{ "0F+D3", "psrlq", { mm, mm_m64 },				"Shift Packed Data Right Logical" },
		{ "66+0F+D3", "psrlq", { xmm, xmm_m128 },		"Shift Packed Data Right Logical" },
		{ "0F+D4", "paddq", { mm, mm_m64 },				"Add Packed Quadword Integers" },
		{ "66+0F+D4", "paddq", { xmm, xmm_m128 },		"Add Packed Quadword Integers" },
		{ "0F+D5", "pmullw", { mm, mm_m64 },			"Multiply Packed Signed Integers and Store Low Result" },
		{ "66+0F+D5", "pmullw", { xmm, xmm_m128 },		"Multiply Packed Signed Integers and Store Low Result" },
		{ "66+0F+D6", "movq", { xmm_m64, xmm },			"Move Quadword" },
		{ "F3+0F+D6", "movq2dq", { xmm, mm },			"Move Quadword from MMX Technology to XMM Register" },
		{ "F2+0F+D6", "movdq2q", { mm, xmm },			"Move Quadword from XMM to MMX Technology Register" },
		{ "0F+D7", "pmovmskb", { r32, mm },				"Move Byte Mask" },
		{ "66+0F+D7", "pmovmskb", { r32, xmm },			"Move Byte Mask" },
		{ "0F+D8", "psubusb", { mm, mm_m64 },			"Subtract Packed Unsigned Integers with Unsigned Saturation" },
		{ "66+0F+D8", "psubusb", { xmm, xmm_m128 },		"Subtract Packed Unsigned Integers with Unsigned Saturation" },
		{ "0F+D9", "psubusw", { mm, mm_m64 },			"Subtract Packed Unsigned Integers with Unsigned Saturation" },
		{ "66+0F+D9", "psubusw", { xmm, xmm_m128 },		"Subtract Packed Unsigned Integers with Unsigned Saturation" },
		{ "0F+DA", "pminub", { mm, mm_m64 },			"Minimum of Packed Unsigned Byte Integers" },
		{ "66+0F+DA", "pminub", { xmm, xmm_m128 },		"Minimum of Packed Unsigned Byte Integers" },
		{ "0F+DB", "pand", { mm, mm_m64 },				"Logical AND" },
		{ "66+0F+DB", "pand", { xmm, xmm_m128 },		"Logical AND" },
		{ "0F+DC", "paddusb", { mm, mm_m64 },			"Add Packed Unsigned Integers with Unsigned Saturation" },
		{ "66+0F+DC", "paddusb", { xmm, xmm_m128 },		"Add Packed Unsigned Integers with Unsigned Saturation" },
		{ "0F+DD", "paddusw", { mm, mm_m64 },			"Add Packed Unsigned Integers with Unsigned Saturation" },
		{ "66+0F+DD", "paddusw", { xmm, xmm_m128 },		"Add Packed Unsigned Integers with Unsigned Saturation" },
		{ "0F+DE", "pmaxub", { mm, mm_m64 },			"Maximum of Packed Unsigned Byte Integers" },
		{ "66+0F+DE", "pmaxub", { xmm, xmm_m128 },		"Maximum of Packed Unsigned Byte Integers" },
		{ "0F+DF", "pandn", { mm, mm_m64 },				"Logical AND NOT" },
		{ "66+0F+DF", "pandn", { xmm, xmm_m128 },		"Logical AND NOT" },
		{ "0F+E0", "pavgb", { mm, mm_m64 },				"Average Packed Integers" },
		{ "66+0F+E0", "pavgb", { xmm, xmm_m128 },		"Average Packed Integers" },
		{ "0F+E1", "psraw", { mm, mm_m64 },				"Shift Packed Data Right Arithmetic" },
		{ "66+0F+E1", "psraw", { xmm, xmm_m128 },		"Shift Packed Data Right Arithmetic" },
		{ "0F+E2", "psrad", { mm, mm_m64 },				"Shift Packed Data Right Arithmetic" },
		{ "66+0F+E2", "psrad", { xmm, xmm_m128 },		"Shift Packed Data Right Arithmetic" },
		{ "0F+E3", "pavgw", { mm, mm_m64 },				"Average Packed Integers" },
		{ "66+0F+E3", "pavgw", { xmm, xmm_m128 },		"Average Packed Integers" },
		{ "0F+E4", "pmulhuw", { mm, mm_m64 },			"Multiply Packed Unsigned Integers and Store High Result" },
		{ "66+0F+E4", "pmulhuw", { xmm, xmm_m128 },		"Multiply Packed Unsigned Integers and Store High Result" },
		{ "0F+E5", "pmulhw", { mm, mm_m64 },			"Multiply Packed Signed Integers and Store High Result" },
		{ "66+0F+E5", "pmulhw", { xmm, xmm_m128 },		"Multiply Packed Signed Integers and Store High Result" },
		{ "F2+0F+E6", "cvtpd2dq", { xmm, xmm_m128 },	"Convert Packed Double-FP Values to DW Integers" },
		{ "66+0F+E6", "cvttpd2dq", { xmm, xmm_m128 },	"Convert with Trunc. Packed Double-FP Values to DW Integers" },
		{ "F3+0F+E6", "cvtdq2pd", { xmm, xmm_m128 },	"Convert Packed DW Integers to Double-FP Values" },
		{ "0F+E7", "movntq", { m64, mm },				"Store of Quadword Using Non-Temporal Hint" },
		{ "66+0F+E7", "movntdq", { m128, xmm },			"Store Double Quadword Using Non-Temporal Hint" },
		{ "0F+E8", "psubsb", { mm, mm_m64 },			"Subtract Packed Signed Integers with Signed Saturation" },
		{ "66+0F+E8", "psubsb", { xmm, xmm_m128 },		"Subtract Packed Signed Integers with Signed Saturation" },
		{ "0F+E9", "psubsw", { mm, mm_m64 },			"Subtract Packed Signed Integers with Signed Saturation" },
		{ "66+0F+E9", "psubsw", { xmm, xmm_m128 },		"Subtract Packed Signed Integers with Signed Saturation" },
		{ "0F+EA", "pminsw", { mm, mm_m64 },			"Minimum of Packed Signed Word Integers" },
		{ "66+0F+EA", "pminsw", { xmm, xmm_m128 },		"Minimum of Packed Signed Word Integers" },
		{ "0F+EB", "por", { mm, mm_m64 },				"Bitwise Logical OR" },
		{ "66+0F+EB", "por", { xmm, xmm_m128 },			"Bitwise Logical OR" },
		{ "0F+EC", "paddsb", { mm, mm_m64 },			"Add Packed Signed Integers with Signed Saturation" },
		{ "66+0F+EC", "paddsb", { xmm, xmm_m128 },		"Add Packed Signed Integers with Signed Saturation" },
		{ "0F+ED", "paddsw", { mm, mm_m64 },			"Add Packed Signed Integers with Signed Saturation" },
		{ "66+0F+ED", "paddsw", { xmm, xmm_m128 },		"Add Packed Signed Integers with Signed Saturation" },
		{ "0F+EE", "pmaxsw", { mm, mm_m64 },			"Maximum of Packed Signed Word Integers" },
		{ "66+0F+EE", "pmaxsw", { xmm, xmm_m128 },		"Maximum of Packed Signed Word Integers" },
		{ "0F+EF", "pxor", { mm, mm_m64 },				"Logical Exclusive OR" },
		{ "66+0F+EF", "pxor", { xmm, xmm_m128 },		"Logical Exclusive OR" },
		{ "F2+0F+F0", "lddqu", { xmm, m128 },			"Load Unaligned Integer 128 Bits" },
		{ "0F+F1", "psllw", { mm, mm_m64 },				"Shift Packed Data Left Logical" },
		{ "66+0F+F1", "psllw", { xmm, xmm_m128 },		"Shift Packed Data Left Logical" },
		{ "0F+F2", "pslld", { mm, mm_m64 },				"Shift Packed Data Left Logical" },
		{ "66+0F+F2", "pslld", { xmm, xmm_m128 },		"Shift Packed Data Left Logical" },
		{ "0F+F3", "psllq", { mm, mm_m64 },				"Shift Packed Data Left Logical" },
		{ "66+0F+F3", "psllq", { xmm, xmm_m128 },		"Shift Packed Data Left Logical" },
		{ "0F+F4", "pmuludq", { mm, mm_m64 },			"Multiply Packed Unsigned DW Integers" },
		{ "66+0F+F4", "pmuludq", { xmm, xmm_m128 },		"Multiply Packed Unsigned DW Integers" },
		{ "0F+F5", "pmaddwd", { mm, mm_m64 },			"Multiply and Add Packed Integers" },
		{ "66+0F+F5", "pmaddwd", { xmm, xmm_m128 },		"Multiply and Add Packed Integers" },
		{ "0F+F6", "psadbw", { mm, mm_m64 },			"Compute Sum of Absolute Differences" },
		{ "66+0F+F6", "psadbw", { xmm, xmm_m128 },		"Compute Sum of Absolute Differences" },
		{ "0F+F7", "maskmovq", { m64, mm, mm },			"Store Selected Bytes of Quadword" },
		{ "66+0F+F7", "maskmovdqu", { m128, xmm, xmm },	"Store Selected Bytes of Double Quadword" },
		{ "0F+F8", "psubb", { mm, mm_m64 },				"Subtract Packed Integers" },
		{ "66+0F+F8", "psubb", { xmm, xmm_m128 },		"Subtract Packed Integers" },
		{ "0F+F9", "psubw", { mm, mm_m64 },				"Subtract Packed Integers" },
		{ "66+0F+F9", "psubw", { xmm, xmm_m128 },		"Subtract Packed Integers" },
		{ "0F+FA", "psubd", { mm, mm_m64 },				"Subtract Packed Integers" },
		{ "66+0F+FA", "psubd", { xmm, xmm_m128 },		"Subtract Packed Integers" },
		{ "0F+FB", "psubq", { mm, mm_m64 },				"Subtract Packed Quadword Integers" },
		{ "66+0F+FB", "psubq", { xmm, xmm_m128 },		"Subtract Packed Quadword Integers" },
		{ "0F+FC", "paddb", { mm, mm_m64 },				"Add Packed Integers" },
		{ "66+0F+FC", "paddb", { xmm, xmm_m128 },		"Add Packed Integers" },
		{ "0F+FD", "paddw", { mm, mm_m64 },				"Add Packed Integers" },
		{ "66+0F+FD", "paddw", { xmm, xmm_m128 },		"Add Packed Integers" },
		{ "0F+FE", "paddd", { mm, mm_m64 },				"Add Packed Integers" },
		{ "66+0F+FE", "paddd", { xmm, xmm_m128 },		"Add Packed Integers" },
		{ "10", "adc", { r_m8, r8 },					"Add with Carry" },
		{ "11", "adc", { r_m16_32, r16_32 },			"Add with Carry" },
		{ "12", "adc", { r8, r_m8 },					"Add with Carry" },
		{ "13", "adc", { r16_32, r_m16_32 },			"Add with Carry" },
		{ "14", "adc", { AL, imm8 },					"Add with Carry" },
		{ "15", "adc", { EAX, imm16_32 },				"Add with Carry" },
		{ "16", "push", { SS },							"Push Stack Segment onto the stack" },
		{ "17", "pop", { SS },							"Pop Stack Segment off of the stack" },
		{ "18", "sbb", { r_m8, r8 },					"Integer Subtraction with Borrow" },
		{ "19", "sbb", { r_m16_32, r16_32 },			"Integer Subtraction with Borrow" },
		{ "1A", "sbb", { r8, r_m8 },					"Integer Subtraction with Borrow" },
		{ "1B", "sbb", { r16_32, r_m16_32 },			"Integer Subtraction with Borrow" },
		{ "1C", "sbb", { AL, imm8 },					"Integer Subtraction with Borrow" },
		{ "1D", "sbb", { EAX, imm16_32 },				"Integer Subtraction with Borrow" },
		{ "1E", "push", { DS },							"Push Data Segment onto the stack" },
		{ "1F", "pop", { DS },							"Pop Data Segment off of the stack" },
		{ "20", "and", { r_m8, r8 },					"Logical AND" },
		{ "21", "and", { r_m16_32, r16_32 },			"Logical AND" },
		{ "22", "and", { r8, r_m8 },					"Logical AND" },
		{ "23", "and", { r16_32, r_m16_32 },			"Logical AND" },
		{ "24", "and", { AL, imm8 },					"Logical AND" },
		{ "25", "and", { EAX, imm16_32 },				"Logical AND" },
		{ "27", "daa", { AL },							"Decimal Adjust AL after Addition" },
		{ "28", "sub", { r_m8, r8 },					"Subtract" },
		{ "29", "sub", { r_m16_32, r16_32 },			"Subtract" },
		{ "2A", "sub", { r8, r_m8 },					"Subtract" },
		{ "2B", "sub", { r16_32, r_m16_32 },			"Subtract" },
		{ "2C", "sub", { AL, imm8 },					"Subtract" },
		{ "2D", "sub", { EAX, imm16_32 },				"Subtract" },
		{ "2F", "das", { AL },							"Decimal Adjust AL after Subtraction" },
		{ "30", "xor", { r_m8, r8 },					"Logical Exclusive OR" },
		{ "31", "xor", { r_m16_32, r16_32 },			"Logical Exclusive OR" },
		{ "32", "xor", { r8, r_m8 },					"Logical Exclusive OR" },
		{ "33", "xor", { r16_32, r_m16_32 },			"Logical Exclusive OR" },
		{ "34", "xor", { AL, imm8 },					"Logical Exclusive OR" },
		{ "35", "xor", { EAX, imm16_32 },				"Logical Exclusive OR" },
		{ "37", "aaa", { AL, AH },						"ASCII Adjust After Addition" },
		{ "38", "cmp", { r_m8, r8 },					"Compare Two Operands" },
		{ "39", "cmp", { r_m16_32, r16_32 },			"Compare Two Operands" },
		{ "3A", "cmp", { r8, r_m8 },					"Compare Two Operands" },
		{ "3B", "cmp", { r16_32, r_m16_32 },			"Compare Two Operands" },
		{ "3C", "cmp", { AL, imm8 },					"Compare Two Operands" },
		{ "3D", "cmp", { EAX, imm16_32 },				"Compare Two Operands" },
		{ "3F", "aas", { AL, AH },						"ASCII Adjust AL After Subtraction" },
		{ "40+r", "inc", { r16_32 },					"Increment by 1" },
		{ "48+r", "dec", { r16_32 },					"Decrement by 1" },
		{ "50+r", "push", { r16_32 },					"Push Word, Doubleword or Quadword Onto the Stack" },
		{ "58+r", "pop", { r16_32 },					"Pop a Value from the Stack" },
		{ "60", "pushad", {  },							"Push All General-Purpose Registers" },
		{ "61", "popad", {  },							"Pop All General-Purpose Registers" },
		{ "62", "bound", { r16_32, m16_32_and_16_32 },	"Check Array Index Against Bounds" },
		{ "63", "arpl", { r_m16, r16 },					"Adjust RPL Field of Segment Selector" },
		{ "63", "arpl", { r_m16, r16 },					"Adjust RPL Field of Segment Selector" },
		{ "68", "push", { imm16_32 },					"Push Word, Doubleword or Quadword Onto the Stack" },
		{ "69", "imul", { r16_32, r_m16_32, imm16_32 },	"Signed Multiply" },
		{ "6A", "push", { imm8 },						"Push Word, Doubleword or Quadword Onto the Stack" },
		{ "6B", "imul", { r16_32, r_m16_32, imm8 },		"Signed Multiply" },
		{ "6C", "insb", {  },							"Input from Port to String" },
		{ "6D", "insd", {  },							"Input from Port to String" },
		{ "6E", "outsb", {  },							"Output String to Port" },
		{ "6F", "outsd", {  },							"Output String to Port" },
		{ "70", "jo short", { rel8 },					"Jump short if overflow (OF=1)" },
		{ "71", "jno short", { rel8 },					"Jump short if not overflow (OF=0))" },
		{ "72", "jb short", { rel8 },					"Jump short if below/not above or equal/carry (CF=1)" },
		{ "73", "jae short", { rel8 },					"Jump short if not below/above or equal/not carry (CF=0))" },
		{ "74", "je short", { rel8 },					"Jump short if zero/equal (ZF=1)" },
		{ "75", "jne short", { rel8 },					"Jump short if not zero/not equal (ZF=0)" },
		{ "76", "jna short", { rel8 },					"Jump short if below or equal/not above (CF=1 OR ZF=1)" },
		{ "77", "ja short", { rel8 },					"Jump short if not below or equal/above (CF=0 AND ZF=0)" },
		{ "78", "js short", { rel8 },					"Jump short if sign (SF=1)" },
		{ "79", "jns short", { rel8 },					"Jump short if not sign (SF=0)" },
		{ "7A", "jp short", { rel8 },					"Jump short if parity/parity even (PF=1)" },
		{ "7B", "jnp short", { rel8 },					"Jump short if not parity/parity odd (PF=0)" },
		{ "7C", "jl short", { rel8 },					"Jump short if less/not greater (SF!=OF)" },
		{ "7D", "jge short", { rel8 },					"Jump short if not less/greater or equal (SF=OF)" },
		{ "7E", "jle short", { rel8 },					"Jump short if less or equal/not greater ((ZF=1) OR (SF!=OF))" },
		{ "7F", "jg short", { rel8 },					"Jump short if not less nor equal/greater ((ZF=0) AND (SF=OF))" },
		{ "80+m0", "add", { r_m8, imm8 },				"Add" },
		{ "80+m1", "or", { r_m8, imm8 },				"Logical Inclusive OR" },
		{ "80+m2", "adc", { r_m8, imm8 },				"Add with Carry" },
		{ "80+m3", "sbb", { r_m8, imm8 },				"Integer Subtraction with Borrow" },
		{ "80+m4", "and", { r_m8, imm8 },				"Logical AND" },
		{ "80+m5", "sub", { r_m8, imm8 },				"Subtract" },
		{ "80+m6", "xor", { r_m8, imm8 },				"Logical Exclusive OR" },
		{ "80+m7", "cmp", { r_m8, imm8 },				"Compare Two Operands" },
		{ "81+m0", "add", { r_m16_32, imm16_32 },		"Add" },
		{ "81+m1", "or", { r_m16_32, imm16_32 },		"Logical Inclusive OR" },
		{ "81+m2", "adc", { r_m16_32, imm16_32 },		"Add with Carry" },
		{ "81+m3", "sbb", { r_m16_32, imm16_32 },		"Integer Subtraction with Borrow" },
		{ "81+m4", "and", { r_m16_32, imm16_32 },		"Logical AND" },
		{ "81+m5", "sub", { r_m16_32, imm16_32 },		"Subtract" },
		{ "81+m6", "xor", { r_m16_32, imm16_32 },		"Logical Exclusive OR" },
		{ "81+m7", "cmp", { r_m16_32, imm16_32 },		"Compare Two Operands" },
		{ "82+m0", "add", { r_m8, imm8 },				"Add" },
		{ "82+m1", "or", { r_m8, imm8 },				"Logical Inclusive OR" },
		{ "82+m2", "adc", { r_m8, imm8 },				"Add with Carry" },
		{ "82+m3", "sbb", { r_m8, imm8 },				"Integer Subtraction with Borrow" },
		{ "82+m4", "and", { r_m8, imm8 },				"Logical AND" },
		{ "82+m5", "sub", { r_m8, imm8 },				"Subtract" },
		{ "82+m6", "xor", { r_m8, imm8 },				"Logical Exclusive OR" },
		{ "82+m7", "cmp", { r_m8, imm8 },				"Compare Two Operands" },
		{ "83+m0", "add", { r_m16_32, imm8 },			"Add" },
		{ "83+m1", "or", { r_m16_32, imm8 },			"Logical Inclusive OR" },
		{ "83+m2", "adc", { r_m16_32, imm8 },			"Add with Carry" },
		{ "83+m3", "sbb", { r_m16_32, imm8 },			"Integer Subtraction with Borrow" },
		{ "83+m4", "and", { r_m16_32, imm8 },			"Logical AND" },
		{ "83+m5", "sub", { r_m16_32, imm8 },			"Subtract" },
		{ "83+m6", "xor", { r_m16_32, imm8 },			"Logical Exclusive OR" },
		{ "83+m7", "cmp", { r_m16_32, imm8 },			"Compare Two Operands" },
		{ "84", "test", { r_m8, r8 },					"Logical Compare" },
		{ "85", "test", { r_m16_32, r16_32 },			"Logical Compare" },
		{ "86", "xchg", { r_m8, r8 },					"Exchange Register/Memory with Register" },
		{ "87", "xchg", { r_m16_32, r16_32 },			"Exchange Register/Memory with Register" },
		{ "88", "mov", { r_m8, r8 },					"Move" },
		{ "89", "mov", { r_m16_32, r16_32 },			"Move" },
		{ "8A", "mov", { r8, r_m8 },					"Move" },
		{ "8B", "mov", { r16_32, r_m16_32 },			"Move" },
		{ "8C", "mov", { m16, Sreg },					"Move" },
		{ "8D", "lea", { r16_32, m32 },					"Load Effective Address" },
		{ "8E", "mov", { Sreg, r_m16 },					"Move" },
		{ "8F", "pop", { r_m16_32 },					"Pop a Value from the Stack" },
		{ "90", "nop", {  },							"No Operation" },
		{ "90+r", "xchg", { EAX, r16_32 },				"Exchange Register/Memory with Register" },
		{ "98", "cbw", { AX, AL },						"Convert Byte to Word" },
		{ "99", "cwd", { AX, AL },						"Convert Doubleword to Quadword" },
		{ "9A", "callf", { ptr16_32 },					"Call Procedure" },
		{ "9B", "fwait", {  },							"Check pending unmasked floating-point exceptions" },
		{ "9C", "pushfd", {  },							"Push EFLAGS Register onto the Stack" },
		{ "9D", "popfd", {  },							"Pop Stack into EFLAGS Register" },
		{ "9E", "sahf", { AH },							"Store AH into Flags" },
		{ "9F", "lahf", { AH },							"Load Status Flags into AH Register" },
		{ "A0", "mov", { AL, moffs8 },					"Move" },
		{ "A1", "mov", { EAX, moffs16_32 },				"Move" },
		{ "A2", "mov", { moffs8, AL },					"Move" },
		{ "A3", "mov", { moffs16_32, EAX },				"Move" },
		{ "A4", "movsb", {  },							"Move Data from String to String" },
		{ "A5", "movsw", {  },							"Move Data from String to String" },
		{ "A6", "cmpsb", {  },							"Compare String Operands" },
		{ "A7", "cmpsw", {  },							"Compare String Operands" },
		{ "A8", "test", { AL, imm8 },					"Logical Compare" },
		{ "A9", "test", { EAX, imm16_32 },				"Logical Compare" },
		{ "AA", "stosb", {  },							"Store String" },
		{ "AB", "stosw", {  },							"Store String" },
		{ "AC", "lodsb", {  },							"Load String" },
		{ "AD", "lodsw", {  },							"Load String" },
		{ "AE", "scasb", {  },							"Scan String" },
		{ "AF", "scasw", {  },							"Scan String" },
		{ "B0+r", "mov", { r8, imm8 },					"Move" },
		{ "B8+r", "mov", { r16_32, imm16_32 },			"Move" },
		{ "C0+m0", "rol", { r_m8, imm8 },				"Rotate" },
		{ "C0+m1", "ror", { r_m8, imm8 },				"Rotate" },
		{ "C0+m2", "rcl", { r_m8, imm8 },				"Rotate" },
		{ "C0+m3", "rcr", { r_m8, imm8 },				"Rotate" },
		{ "C0+m4", "shl", { r_m8, imm8 },				"Shift" },
		{ "C0+m5", "shr", { r_m8, imm8 },				"Shift" },
		{ "C0+m6", "sal", { r_m8, imm8 },				"Shift" },
		{ "C0+m7", "sar", { r_m8, imm8 },				"Shift" },
		{ "C1+m0", "rol", { r_m16_32, imm8 },			"Rotate" },
		{ "C1+m1", "ror", { r_m16_32, imm8 },			"Rotate" },
		{ "C1+m2", "rcl", { r_m16_32, imm8 },			"Rotate" },
		{ "C1+m3", "rcr", { r_m16_32, imm8 },			"Rotate" },
		{ "C1+m4", "shl", { r_m16_32, imm8 },			"Shift" },
		{ "C1+m5", "shr", { r_m16_32, imm8 },			"Shift" },
		{ "C1+m6", "sal", { r_m16_32, imm8 },			"Shift" },
		{ "C1+m7", "sar", { r_m16_32, imm8 },			"Shift" },
		{ "C2", "ret", { imm16 },						"Return from procedure" },
		{ "C3", "retn", {  },							"Return from procedure" },
		{ "C4", "les", { ES, r16_32, m16_32_and_16_32 },"Load Far Pointer" },
		{ "C5", "lds", { DS, r16_32, m16_32_and_16_32 },"Load Far Pointer" },
		{ "C6", "mov", { r_m8, imm8 },					"Move" },
		{ "C7", "mov", { r_m16_32, imm16_32 },			"Move" },
		{ "66+C7", "mov", { r_m16_32, imm16 },			"Move" },
		{ "C8", "enter", { EBP, imm16, imm8 },			"Make Stack Frame for Procedure Parameters" },
		{ "C9", "leave", { EBP },						"High Level Procedure Exit" },
		{ "CA", "retf", { imm16 },						"Return from procedure" },
		{ "CB", "retf", {  },							"Return from procedure" },
		{ "CC", "int 3", {  },							"Call to Interrupt Procedure" },
		{ "CD", "int", { imm8 },						"Call to Interrupt Procedure" },
		{ "CE", "into", {  },							"Call to Interrupt Procedure" },
		{ "CF", "iretd", {  },							"Interrupt Return" },
		{ "D0+m0", "rol", { r_m8, one },				"Rotate" },
		{ "D0+m1", "ror", { r_m8, one },				"Rotate" },
		{ "D0+m2", "rcl", { r_m8, one },				"Rotate" },
		{ "D0+m3", "rcr", { r_m8, one },				"Rotate" },
		{ "D0+m4", "shl", { r_m8, one },				"Shift" },
		{ "D0+m5", "shr", { r_m8, one },				"Shift" },
		{ "D0+m6", "shl", { r_m8, one },				"Shift" },
		{ "D0+m7", "shr", { r_m8, one },				"Shift" },
		{ "D1+m0", "rol", { r_m16_32, one },			"Rotate" },
		{ "D1+m1", "ror", { r_m16_32, one },			"Rotate" },
		{ "D1+m2", "rcl", { r_m16_32, one },			"Rotate" },
		{ "D1+m3", "rcr", { r_m16_32, one },			"Rotate" },
		{ "D1+m4", "shl", { r_m16_32, one },			"Shift" },
		{ "D1+m5", "shr", { r_m16_32, one },			"Shift" },
		{ "D1+m6", "shl", { r_m16_32, one },			"Shift" },
		{ "D1+m7", "shr", { r_m16_32, one },			"Shift" },
		{ "D2+m0", "rol", { r_m8, CL },					"Rotate" },
		{ "D2+m1", "ror", { r_m8, CL },					"Rotate" },
		{ "D2+m2", "rcl", { r_m8, CL },					"Rotate" },
		{ "D2+m3", "rcr", { r_m8, CL },					"Rotate" },
		{ "D2+m4", "shl", { r_m8, CL },					"Shift" },
		{ "D2+m5", "shr", { r_m8, CL },					"Shift" },
		{ "D2+m6", "shl", { r_m8, CL },					"Shift" },
		{ "D2+m7", "shr", { r_m8, CL },					"Shift" },
		{ "D3+m0", "rol", { r_m16_32, CL },				"Rotate" },
		{ "D3+m1", "ror", { r_m16_32, CL },				"Rotate" },
		{ "D3+m2", "rcl", { r_m16_32, CL },				"Rotate" },
		{ "D3+m3", "rcr", { r_m16_32, CL },				"Rotate" },
		{ "D3+m4", "shl", { r_m16_32, CL },				"Shift" },
		{ "D3+m5", "shr", { r_m16_32, CL },				"Shift" },
		{ "D3+m6", "shl", { r_m16_32, CL },				"Shift" },
		{ "D3+m7", "shr", { r_m16_32, CL },				"Shift" },
		{ "D4", "aam", { AL, AH, imm8 },				"ASCII Adjust AX After Multiply" },
		{ "D5", "aad", { AL, AH, imm8 },				"ASCII Adjust AX Before Division" },
		{ "D6", "setalc", { AL },						"Set AL If Carry" },
		{ "D7", "xlatb", { AL },						"Table Look-up Translation" },
		{ "D8+m8", "fadd", { ST, STi },					"Add" },
		{ "D8+m9", "fmul", { ST, STi },					"Multiply" },
		{ "D8+mA", "fcom", { ST, STi },					"Compare Real" },
		{ "D8+mB", "fcomp", { ST, STi },				"Compare Real and Pop" },
		{ "D8+mC", "fsub", { ST, STi },					"Subtract" },
		{ "D8+mD", "fsubr", { ST, STi },				"Reverse Subtract" },
		{ "D8+mE", "fdiv", { ST, STi },					"Divide" },
		{ "D8+mF", "fdivr", { ST, STi },				"Reverse Divide" },
		{ "D8+m0", "fadd", { STi },						"Add" },
		{ "D8+m1", "fmul", { STi },						"Multiply" },
		{ "D8+m2", "fcom", { STi },						"Compare Real" },
		{ "D8+m3", "fcomp", { STi },					"Compare Real and Pop" },
		{ "D8+m4", "fsub", { STi },						"Subtract" },
		{ "D8+m5", "fsubr", { STi },					"Reverse Subtract" },
		{ "D8+m6", "fdiv", { STi },						"Divide" },
		{ "D8+m7", "fdivr", { STi },					"Reverse Divide" },
		{ "D9+m0", "fld", { STi },						"Load Floating Point Value" },
		{ "D9+m1", "fxch", { STi },						"Exchange Register Contents" },
		{ "D9+m2", "fst", { STi },						"Store Floating Point Value" },
		{ "D9+m3", "fstp", { STi },						"Store Floating Point Value and Pop" },
		{ "D9+m4", "fldenv", { STi },					"Load x87 FPU Environment" },
		{ "D9+m5", "fldcw", { STi },					"Load x87 FPU Control Word" },
		{ "D9+m6", "fnstenv", { STi },					"Store x87 FPU Environment" },
		{ "D9+m7", "fnstcw", { STi },					"Store x87 FPU Control Word" },
		{ "DA+m8", "fcmovb", { ST, STi },				"FP Conditional Move - below (CF=1)" },
		{ "DA+m9", "fcmove", { ST, STi },				"FP Conditional Move - equal (ZF=1)" },
		{ "DA+mA", "fcmovbe", { ST, STi },				"FP Conditional Move - below or equal (CF=1 or ZF=1)" },
		{ "DA+mB", "fcmovu", { ST, STi },				"FP Conditional Move - unordered (PF=1)" },
		{ "DA+mC", "fisub", { ST, STi },				"Subtract" },
		{ "DA+mD", "fisubr", { ST, STi },				"Reverse Subtract" },
		{ "DA+mE", "fidiv", { ST, STi },				"Divide" },
		{ "DA+mF", "fidivr", { ST, STi },				"Reverse Divide" },
		{ "DA+m0", "fiadd", { STi },					"Add" },
		{ "DA+m1", "fimul", { STi },					"Multiply" },
		{ "DA+m2", "ficom", { STi },					"Compare Real" },
		{ "DA+m3", "ficomp", { STi },					"Compare Real and Pop" },
		{ "DA+m4", "fisub", { STi },					"Subtract" },
		{ "DA+m5", "fisubr", { STi },					"Reverse Subtract" },
		{ "DA+m6", "fidiv", { STi },					"Divide" },
		{ "DA+m7", "fidivr", { STi },					"Reverse Divide" },
		{ "DB+m8", "fcmovnb", { ST, STi },				"FP Conditional Move - not below (CF=0)" },
		{ "DB+m9", "fcmovne", { ST, STi },				"FP Conditional Move - not equal (ZF=0)" },
		{ "DB+mA", "fcmovnbe", { ST, STi },				"FP Conditional Move - below or equal (CF=0 and ZF=0)" },
		{ "DB+mB", "fcmovnu", { ST, STi },				"FP Conditional Move - not unordered (PF=0)" },
		{ "DB+m0", "fild", { STi },						"Load Integer" },
		{ "DB+m1", "fisttp", { STi },					"Store Integer with Truncation and Pop" },
		{ "DB+m2", "fist", { STi },						"Store Integer" },
		{ "DB+m3", "fistp", { STi },					"Store Integer and Pop" },
		{ "DB+m4", "finit", { STi },					"Initialize Floating-Point Unit" },
		{ "DB+m5", "fucomi", { STi },					"Unordered Compare Floating Point Values and Set EFLAGS" },
		{ "DB+m6", "fcomi", { STi },					"Compare Floating Point Values and Set EFLAGS" },
		{ "DB+m7", "fstp", { STi },						"Store Floating Point Value and Pop" },
		{ "DC+m8", "fadd", { STi, ST },					"Add" },
		{ "DC+m9", "fmul", { STi, ST },					"Multiply" },
		{ "DC+mA", "fcom", { STi, ST },					"Compare Real" },
		{ "DC+mB", "fcomp", { STi, ST },				"Compare Real and Pop" },
		{ "DC+mC", "fsub", { STi, ST },					"Subtract" },
		{ "DC+mD", "fsubr", { STi, ST },				"Reverse Subtract" },
		{ "DC+mE", "fdiv", { STi, ST },					"Divide" },
		{ "DC+mF", "fdivr", { STi, ST },				"Reverse Divide" },
		{ "DC+m0", "fadd", { STi },						"Add" },
		{ "DC+m1", "fmul", { STi },						"Multiply" },
		{ "DC+m2", "fcom", { STi },						"Compare Real" },
		{ "DC+m3", "fcomp", { STi },					"Compare Real and Pop" },
		{ "DC+m4", "fsub", { STi },						"Subtract" },
		{ "DC+m5", "fsubr", { STi },					"Reverse Subtract" },
		{ "DC+m6", "fdiv", { STi },						"Divide" },
		{ "DC+m7", "fdivr", { STi },					"Reverse Divide" },
		{ "DD+m8", "ffree", { STi },					"Free Floating-Point Register" },
		{ "DD+m0", "fld", { STi },						"Load Floating Point Value" },
		{ "DD+m1", "fisttp", { STi },					"Store Integer with Truncation and Pop" },
		{ "DD+m2", "fst", { STi },						"Store Floating Point Value" },
		{ "DD+m3", "fstp", { STi },						"Store Floating Point Value and Pop" },
		{ "DD+m4", "frstor", { STi },					"Restore x87 FPU State" },
		{ "DD+m5", "fucomp", { STi },					"Unordered Compare Floating Point Values and Pop" },
		{ "DD+m6", "fnsave", { STi },					"Store x87 FPU State" },
		{ "DD+m7", "fnstsw", { STi },					"Store x87 FPU Status Word" },
		{ "DE+m8", "faddp", { ST, STi },				"Add and Pop" },
		{ "DE+m9", "fmulp", { ST, STi },				"Multiply and Pop" },
		{ "DE+mA", "ficom", { ST, STi },				"Compare Real" },
		{ "DE+mB", "ficomp", { ST, STi },				"Compare Real and Pop" },
		{ "DE+mC", "fsubrp", { ST, STi },				"Reverse Subtract and Pop" },
		{ "DE+mD", "fsubp", { ST, STi },				"Subtract and Pop" },
		{ "DE+mE", "fdivrp", { ST, STi },				"Reverse Divide and Pop" },
		{ "DE+mF", "fdivp", { ST, STi },				"Divide and Pop" },
		{ "DE+m0", "fiadd", { STi },					"Add" },
		{ "DE+m1", "fimul", { STi },					"Multiply" },
		{ "DE+m2", "ficom", { STi },					"Compare Real" },
		{ "DE+m3", "ficomp", { STi },					"Compare Real and Pop" },
		{ "DE+m4", "fisub", { STi },					"Subtract" },
		{ "DE+m5", "fisubr", { STi },					"Reverse Subtract" },
		{ "DE+m6", "fidiv", { STi },					"Divide" },
		{ "DE+m7", "fdivr", { STi },					"Reverse Divide" },
		{ "DF+m8", "ffreep", { STi },					"Free Floating-Point Register and Pop" },
		{ "DF+m9", "fisttp", { r32 },					"Store Integer with Truncation and Pop" },
		{ "DF+mA", "fist", { STi },						"Store Integer" },
		{ "DF+mB", "fistp", { STi },					"Store Integer and Pop" },
		{ "DF+mC", "fnstsw", { STi },					"Store x87 FPU Status Word" },
		{ "DF+mD", "fucomip", { ST, STi },				"Unordered Compare Floating Point Values and Set EFLAGS and Pop" },
		{ "DF+mE", "fcomip", { ST, STi },				"Compare Floating Point Values and Set EFLAGS and Pop" },
		{ "DF+mF", "fistp", { r64 },					"Store Integer and Pop" },
		{ "DF+m0", "fild", { STi },						"Load Integer" },
		{ "DF+m1", "fisttp", { STi },					"Store Integer with Truncation and Pop" },
		{ "DF+m2", "fist", { STi },						"Store Integer" },
		{ "DF+m3", "fistp", { STi },					"Store Integer and Pop" },
		{ "DF+m4", "fbld", { STi },						"Load Binary Coded Decimal" },
		{ "DF+m5", "fild", { STi },						"Load Integer" },
		{ "DF+m6", "fbstp", { STi },					"Store BCD Integer and Pop" },
		{ "DF+m7", "fistp", { STi },					"Store Integer and Pop" },
		{ "E0", "loopne", { ECX, rel8 },				"Decrement count; Jump short if count!=0 and ZF=0" },
		{ "E1", "loope", { ECX, rel8 },					"Decrement count; Jump short if count!=0 and ZF=1" },
		{ "E2", "loop", { ECX, rel8 },					"Decrement count; Jump short if count!=0" },
		{ "E3", "jecxz", { rel8 },						"Jump short if eCX register is 0" },
		{ "E4", "in", { AL, imm8 },						"Input from Port" },
		{ "E5", "in", { EAX, imm8 },					"Input from Port" },
		{ "E6", "out", { imm8, AL },					"Output to Port" },
		{ "E7", "out", { imm8, EAX },					"Output to Port" },
		{ "E8", "call", { rel16_32 },					"Call Procedure" },
		{ "E9", "jmp", { rel16_32 },					"Jump" },
		{ "EA", "jmpf", { ptr16_32 },					"Jump" },
		{ "EB", "jmp short", { rel8 },					"Jump" },
		{ "EC", "in", { AL, DX },						"Input from Port" },
		{ "ED", "in", { EAX, DX },						"Input from Port" },
		{ "EE", "out", { DX, AL },						"Output to Port" },
		{ "EF", "out", { DX, EAX },						"Output to Port" },
		{ "F1", "int 1", {  },							"Call to Interrupt Procedure" },
		{ "F4", "hlt", {  },							"Halt" },
		{ "F5", "cmc", {  },							"Complement Carry Flag" },
		{ "F6+m0", "test", { r_m8, imm8 },				"Logical Compare" },
		{ "F6+m1", "test", { r_m8, imm8 },				"Logical Compare" },
		{ "F6+m2", "not", { r_m8 },						"One's Complement Negation" },
		{ "F6+m3", "neg", { r_m8 },						"Two's Complement Negation" },
		{ "F6+m4", "mul", { AX, AL, r_m8 },				"Unsigned Multiply" },
		{ "F6+m5", "imul", { AX, AL, r_m8 },			"Signed Multiply" },
		{ "F6+m6", "div", { AX, AL, AX, r_m8 },			"Unigned Divide" },
		{ "F6+m7", "idiv", { AX, AL, AX, r_m8 },		"Signed Divide" },
		{ "F7+m0", "test", { r_m16_32, imm16_32 },		"Logical Compare" },
		{ "F7+m1", "test", { r_m16_32, imm16_32 },		"Logical Compare" },
		{ "F7+m2", "not", { r_m16_32 },					"One's Complement Negation" },
		{ "F7+m3", "neg", { r_m16_32 },					"Two's Complement Negation" },
		{ "F7+m4", "mul", { EDX, EAX, r_m16_32 },		"Unsigned Multiply" },
		{ "F7+m5", "imul", { EDX, EAX, r_m16_32 },		"Signed Multiply" },
		{ "F7+m6", "div", { EDX, EAX, r_m16_32 },		"Unigned Divide" },
		{ "F7+m7", "idiv", { EDX, EAX, r_m16_32 },		"Signed Divide" },
		{ "F8", "clc", {  },							"Clear Carry Flag" },
		{ "F9", "stc", {  },							"Set Carry Flag" },
		{ "FA", "cli", {  },							"Clear Interrupt Flag" },
		{ "FB", "sti", {  },							"Set Interrupt Flag" },
		{ "FC", "cld", {  },							"Clear Direction Flag" },
		{ "FD", "std", {  },							"Set Direction Flag" },
		{ "FE+m0", "inc", { r_m8 },						"Increment by 1" },
		{ "FE+m1", "dec", { r_m8 },						"Decrement by 1" },
		{ "FE+mE", "inc", { r_m8 },						"Increment by 1" },
		{ "FE+mF", "dec", { r_m8 },						"Decrement by 1" },
		{ "FF+m0", "inc", { r_m16_32 },					"Increment by 1" },
		{ "FF+m1", "dec", { r_m16_32 },					"Decrement by 1" },
		{ "FF+m2", "call", { r_m16_32 },				"Call Procedure" },
		{ "FF+m3", "callf", { m16_32_and_16_32 },		"Call Procedure" },
		{ "FF+m4", "jmp", { r_m16_32 },					"Jump" },
		{ "FF+m5", "jmpf", { m16_32_and_16_32 },		"Jump" },
		{ "FF+m6", "push", { r_m16_32 },				"Push Word, Doubleword or Quadword Onto the Stack" },
		{ "FF+m7", "push", { r_m16_32 },				"Push Word, Doubleword or Quadword Onto the Stack" },
	};

	return disa_optable.size() > 0;
}

disa_operand::disa_operand()
{
	n_reg = 0;
	rel8 = 0;
	rel16 = 0;
	rel32 = 0;
	imm8 = 0;
	imm16 = 0;
	imm32 = 0;
	disp8 = 0;
	disp16 = 0;
	disp32 = 0;
	mul = 0;
	opmode = 0;
	flags = 0;

	reg = std::vector<std::uint8_t>(4);
}

disa_operand::~disa_operand()
{
}

std::uint8_t disa_operand::append_reg(const std::uint8_t reg_type)
{
	reg[n_reg++] = (reg_type);
	return reg_type;
}

disa_inst::disa_inst()
{
	data[0] = '\0';
	info = disa_opinfo();

	operands = std::vector<disa_operand>(4);

	address = 0;
	flags = 0;
	len = 0;
}

disa_inst::~disa_inst()
{
	operands.clear();
}

disa_operand disa_inst::src()
{
	if (operands.size() <= 0) return disa_operand();
	return operands[0];
}

disa_operand disa_inst::dest()
{
	if (operands.size() <= 1) return disa_operand();
	return operands[1];
}



namespace mnemonics
{
	const char* const r8_names[] =
	{
		"al",
		"cl",
		"dl",
		"bl",
		"ah",
		"ch",
		"dh",
		"bh"
	};

	const char* const r16_names[] =
	{
		"ax",
		"cx",
		"dx",
		"bx",
		"sp",
		"bp",
		"si",
		"di"
	};

	const char* const r32_names[] =
	{
		"eax",
		"ecx",
		"edx",
		"ebx",
		"esp",
		"ebp",
		"esi",
		"edi"
	};

	const char* const r64_names[] =
	{
		"rax",
		"rcx",
		"rdx",
		"rbx",
		"rsp",
		"rbp",
		"rsi",
		"rdi"
	};

	const char* const xmm_names[] =
	{
		"xmm0",
		"xmm1",
		"xmm2",
		"xmm3",
		"xmm4",
		"xmm5",
		"xmm6",
		"xmm7"
	};

	const char* const mm_names[] =
	{
		"mm0",
		"mm1",
		"mm2",
		"mm3",
		"mm4",
		"mm5",
		"mm6",
		"mm7"
	};

	const char* const sreg_names[] =
	{
		"es",
		"cs",
		"ss",
		"ds",
		"fs",
		"gs",
		"hs",
		"is"
	};

	const char* const dr_names[] = // debug register
	{
		"dr0",
		"dr1",
		"dr2",
		"dr3",
		"dr4",
		"dr5",
		"dr6",
		"dr7"
	};

	const char* const cr_names[] = // control register
	{
		"cr0",
		"cr1",
		"cr2",
		"cr3",
		"cr4",
		"cr5",
		"cr6",
		"cr7"
	};

	const char* const st_names[] = // control register
	{
		"st(0)",
		"st(1)",
		"st(2)",
		"st(3)",
		"st(4)",
		"st(5)",
		"st(6)",
		"st(7)"
	};
}

const std::uint8_t multipliers[] = 
{
	0, 2, 4, 8 // used in SIB
};

const std::uint32_t getm20(const std::uint8_t x)
{
	return x % 32;
}

const std::uint32_t getm40(const std::uint8_t x)
{
	return x % 64;
}

const std::uint32_t finalreg(const std::uint8_t x)
{
	return (x % 64) % 8;
}

const std::uint32_t longreg(const std::uint8_t x)
{
	return (x % 64) / 8;
}


// Stored Prefix flags 
constexpr std::uint16_t PRE_REPNE   		= 0x0001;
constexpr std::uint16_t PRE_REPE   			= 0x0002;
constexpr std::uint16_t PRE_66   			= 0x0004;
constexpr std::uint16_t PRE_67   			= 0x0008;
constexpr std::uint16_t PRE_LOCK 			= 0x0010;
constexpr std::uint16_t PRE_SEG_CS  		= 0x0020;
constexpr std::uint16_t PRE_SEG_SS  		= 0x0040;
constexpr std::uint16_t PRE_SEG_DS  		= 0x0080;
constexpr std::uint16_t PRE_SEG_ES  		= 0x0100;
constexpr std::uint16_t PRE_SEG_FS  		= 0x0200;
constexpr std::uint16_t PRE_SEG_GS  		= 0x0400;

// Prefix bytes
constexpr std::uint8_t OP_LOCK				= 0xF0;
constexpr std::uint8_t OP_REPNE				= 0xF2;
constexpr std::uint8_t OP_REPE				= 0xF3;
constexpr std::uint8_t OP_66				= 0x66;
constexpr std::uint8_t OP_67				= 0x67;
constexpr std::uint8_t OP_SEG_CS			= 0x2E;
constexpr std::uint8_t OP_SEG_SS			= 0x36;
constexpr std::uint8_t OP_SEG_DS			= 0x3E;
constexpr std::uint8_t OP_SEG_ES			= 0x26;
constexpr std::uint8_t OP_SEG_FS			= 0x64;
constexpr std::uint8_t OP_SEG_GS			= 0x65;



disa_inst read(const std::uintptr_t address)
{
	disa_inst p;
	p.address = address;

	std::memcpy(&p.bytes, reinterpret_cast<void*>(address), sizeof(p.bytes) / sizeof(std::uint8_t));
	
	std::uint8_t* at = p.bytes;
	std::uint8_t* prev_at = at;

	for (std::size_t opcode_at = 0; opcode_at < disa_optable.size() - 1; at = prev_at, opcode_at++, p.flags = 0)
	{
		const auto op_info = disa_optable[opcode_at];
		std::uint8_t opcode_byte = std::strtol(op_info.code.substr(0, 2).c_str(), nullptr, 16);
		
		bool show_prefix = false;

		// identify prefix of the instruction
		switch (*at)
		{
		case OP_SEG_CS:
			p.flags |= PRE_SEG_CS;
			*at++;
			break;
		case OP_SEG_SS:
			p.flags |= PRE_SEG_SS;
			*at++;
			break;
		case OP_SEG_DS:
			p.flags |= PRE_SEG_DS;
			*at++;
			break;
		case OP_SEG_ES:
			p.flags |= PRE_SEG_ES;
			*at++;
			break;
		case OP_SEG_FS:
			p.flags |= PRE_SEG_FS;
			*at++;
			break;
		case OP_SEG_GS:
			p.flags |= PRE_SEG_GS;
			*at++;
			break;
		case OP_LOCK:
			p.flags |= PRE_LOCK;
			*at++;

			show_prefix = (opcode_byte != OP_LOCK) ? true : show_prefix;
			break;
		case OP_REPNE:
			p.flags |= PRE_REPNE;
			*at++;

			show_prefix = (opcode_byte != OP_REPNE) ? true : show_prefix;
			break;
		case OP_REPE:
			p.flags |= PRE_REPE; 
			*at++;

			show_prefix = (opcode_byte != OP_REPE) ? true : show_prefix;
			break;
			// I include 66/67 byte prefixes in the opcode table
			// since they're used to imply a different instruction.
			// so dont skip this byte. we need to compare it in the op table.
			// other prefixes are simply tacked onto the text translation (p.data)
		case OP_66:
			p.flags |= PRE_66;
			break;
		case OP_67:
			p.flags |= PRE_67;
			break;
		}

		bool opcode_match = (*at == opcode_byte);
		bool reg_from_opcode_byte = false;

		// This is a hard-coded parse I wrote a while back
		// It's not bad in terms of working consistently.
		// But it is ugly.
		for (std::size_t i = 2; i < 11; i += 3)
		{
			// op_info.code may look like: "83+m0"
			// we want to start at the character after 83
			// and begin parsing the expressions
			if (!(op_info.code.length() > i))
			{
				break;
			}
			else
			{
				// Extended byte?
				if (op_info.code[i] == '+')
				{
					// Check if the opcode byte determines the register
					if (op_info.code[i + 1] == 'r')
					{
						reg_from_opcode_byte = true;

						// this simple check can simplify instructons like inc/dec/push/pop
						// in our opcode table so it can do up to 8 combinations
						// All we have to put is put `40+r` (rather than 40, 41, 42, 43,...)
						opcode_match = (*at >= opcode_byte) && (*at < opcode_byte + 8);
						break;
					}
					else if (op_info.code[i + 1] == 'm' && opcode_match)
					{
						std::string str = "0";
						str += op_info.code[i + 2];
						std::uint8_t n = std::strtol(str.c_str(), nullptr, 16);

						if (n >= 0 && n < 8)
						{
							// for every +8 it switches to a different opcode out of 8
							opcode_match = longreg(*(at + 1)) == n;
						}
						else {
							// for every +8 it switches to a different opcode out of 8
							// IF the mode is 3 / the byte is >= 0xC0
							n -= 8;
							opcode_match = longreg(*(at + 1)) == n && *(at + 1) >= 0xC0;
						}
						break;
					}
					else if (opcode_match)
					{
						// in all other cases, it's an extending byte
						at++;

						opcode_byte = std::strtol(op_info.code.substr(i + 1, 2).c_str(), nullptr, 16);
						opcode_match = (*at == opcode_byte);
					}
				}
			}
		}

		// The bytes after the prefix seem to match the byte(s) 
		// for this particular opcode
		if (opcode_match)
		{
			// So now we can include information about the prefix
			// to our text translation
			if (show_prefix)
			{
				if (p.flags & PRE_LOCK)  p.data += "lock ";
				if (p.flags & PRE_REPNE) p.data += "repne ";
				if (p.flags & PRE_REPE)  p.data += "repe ";
			}

			p.data += op_info.opcode_name + " ";

			// We're ready to move onto the next byte.
			// We can start processing mnemonics 
			at++;

			std::size_t noperands = op_info.operands.size();

			p.operands = std::vector<disa_operand>(noperands); // allocate for the # of operands
			p.info = op_info;

			// append flags which help users identify
			// what type of instruction this is
			switch (noperands)
			{
			case 0:
				break;
			case 1:
				p.flags |= OP_SINGLE; // uses 1 register (source)
				break;
			case 2:
				p.flags |= OP_SRC_DEST; // uses 2 registers (source/destination)
				break;
			default:
				p.flags |= OP_EXTENDED; // uses 3+ registers
				break;
			}

			const std::uint8_t mod_byte_not_first = 255;
			auto prev = mod_byte_not_first;

			// Iterate through all of the operands in this information bit
			for (std::size_t c = 0; c < noperands; c++)
			{
				// c = current operand (index)
				// append this opmode to that of the corresponding operand
				p.operands[c].opmode = op_info.operands[c];

				// Returns the imm8 offset value at `x`
				// and then increases `at` by imm8 size.
				const auto get_imm8 = [&p, &c, &at](auto x, bool constant)
				{
					std::stringstream ss;

					if (!constant)
					{
						p.operands[c].imm8 = *x;
						p.operands[c].flags |= OP_IMM8;

						if (*x > CHAR_MAX)
							ss << "-" << std::setfill('0') << std::setw(2) << std::uppercase << std::hex << static_cast<uint32_t>(((UCHAR_MAX + 1) - p.operands[c].imm8));
						else
						{
							ss << "+" << std::setfill('0') << std::setw(2) << std::uppercase << std::hex << static_cast<uint32_t>(p.operands[c].imm8);
						}
					}
					else 
					{
						p.operands[c].disp8 = *x;
						p.operands[c].flags |= OP_DISP8;

						ss << std::setfill('0') << std::setw(2) << std::uppercase << std::hex << static_cast<uint32_t>(p.operands[c].disp8);
					}

					p.data += ss.str();

					at += sizeof(std::uint8_t);
				};

				// Returns the imm16 offset value at `x`
				// and then increases `at` by imm16 size.
				const auto get_imm16 = [&p, &c, &at](auto x, bool constant)
				{
					std::stringstream ss;

					if (!constant)
					{
						p.operands[c].imm16 = *reinterpret_cast<std::uint16_t*>(x);
						p.operands[c].flags |= OP_IMM16;

						if (*x > INT16_MAX)
							ss << "-" << std::setfill('0') << std::setw(4) << std::uppercase << std::hex << static_cast<uint32_t>(((UINT16_MAX + 1) - p.operands[c].imm16));
						else 
						{
							ss << "+" << std::setfill('0') << std::setw(4) << std::uppercase << std::hex << static_cast<uint32_t>(p.operands[c].imm16);
						}
					}
					else {
						p.operands[c].disp16 = *reinterpret_cast<std::uint16_t*>(x);
						p.operands[c].flags |= OP_DISP16;

						ss << std::setfill('0') << std::setw(4) << std::uppercase << std::hex << static_cast<uint32_t>(p.operands[c].disp16);
					}

					p.data += ss.str();

					at += sizeof(std::uint16_t);
				};

				// Returns the imm32 offset value at `x`
				// and then increases `at` by imm32 size.
				const auto get_imm32 = [&p, &c, &at](auto x, bool constant)
				{
					std::stringstream ss;

					if (!constant)
					{
						p.operands[c].imm32 = *reinterpret_cast<std::uint32_t*>(x);
						p.operands[c].flags |= OP_IMM32;

						if (*x > INT16_MAX)
							ss << "-" << std::setfill('0') << std::setw(8) << std::uppercase << std::hex << ((UINT32_MAX + 1) - p.operands[c].imm32);
						else
						{
							ss << "+" << std::setfill('0') << std::setw(8) << std::uppercase << std::hex << p.operands[c].imm32;
						}
					}
					else
					{
						p.operands[c].disp32 = *reinterpret_cast<std::uint32_t*>(x);
						p.operands[c].flags |= OP_DISP32;

						ss << std::setfill('0') << std::setw(8) << std::uppercase << std::hex << p.operands[c].disp32;
					}

					p.data += ss.str();

					at += sizeof(std::uint32_t);
				};

				const auto get_sib = [&get_imm8, &get_imm32, &p, &at, &c](const std::uint8_t imm)
				{
					// get the SIB byte based on the operand's MOD byte.
					// See http://www.c-jump.com/CIS77/CPU/x86/X77_0100_sib_byte_layout.htm
					// See https://www.cs.uaf.edu/2002/fall/cs301/Encoding%20instructions.htm
					// 
					// To-do: Label the values that make up scale, index, and byte
					// I didn't label too much here so it is pretty indecent atm...
					// 

					const std::uint8_t sib_byte = *++at; // notice we skip to the next byte for this
					const std::uint8_t r1 = longreg(sib_byte);
					const std::uint8_t r2 = finalreg(sib_byte);

					if ((sib_byte + 32) / 32 % 2 == 0 && sib_byte % 32 < 8)
					{
						// 
						p.data += mnemonics::r32_names[p.operands[c].append_reg(r2)];
						p.operands[c].flags |= OP_R32;
					}
					else
					{
						// we need to check the previous byte in this circumstance
						if (r2 == 5 && *(at - 1) < 64)
						{
							p.data += mnemonics::r32_names[p.operands[c].append_reg(r1)];
							p.operands[c].flags |= OP_R32;
						}
						else
						{
							p.data += mnemonics::r32_names[p.operands[c].append_reg(r2)];
							p.data += "+"; // + SIB Base
							p.data += mnemonics::r32_names[p.operands[c].append_reg(r1)];
							p.operands[c].flags |= OP_R32;
						}

						// Calculate SIB Scale
						if (sib_byte / 64)
						{
							p.operands[c].mul = multipliers[sib_byte / 64];

							std::stringstream ss;
							ss << "*" << p.operands[c].mul;

							p.data += ss.str();
						}
					}

					if (imm == sizeof(std::uint8_t))
					{
						get_imm8(at + 1, false);
					}
					else if (imm == sizeof(std::uint32_t) || (imm == 0 && r2 == 5))
					{
						get_imm32(at + 1, false);
					}
				};

				// Gets the relative offset value at `x`
				// and then increases `at` by rel8 size.
				const auto get_rel8 = [&p, &c, &at](auto x)
				{
					// get the current address of where `at` is located
					const std::uint32_t location = p.address + (reinterpret_cast<std::uint32_t>(x) - reinterpret_cast<std::uint32_t>(p.bytes));
					
					// base the 8-bit relative offset on it
					p.operands[c].rel8 = *reinterpret_cast<std::uint8_t*>(x);

					std::stringstream ss;
					ss << std::setfill('0') << std::setw(8) << std::uppercase << std::hex << (location + sizeof(std::uint8_t) + p.operands[c].rel8);
					
					p.data += ss.str();

					at += sizeof(std::uint8_t);
				};

				// Gets the relative offset value at `x`
				// and then increases `at` by rel16 size.
				const auto get_rel16 = [&p, &c, &at](auto x)
				{
					// get the current address of where `at` is located
					const std::uint32_t location = p.address + (reinterpret_cast<std::uint32_t>(x) - reinterpret_cast<std::uint32_t>(p.bytes));
					
					// base the 16-bit relative offset on it
					p.operands[c].rel16 = *reinterpret_cast<std::uint16_t*>(x);

					std::stringstream ss;
					ss << std::setfill('0') << std::setw(8) << std::uppercase << std::hex << (location + sizeof(std::uint16_t) + p.operands[c].rel16);

					p.data += ss.str();

					at += sizeof(std::uint16_t);
				};

				// Gets the relative offset value at `x`
				// and then increases `at` by rel32 size.
				const auto get_rel32 = [&p, &c, &at](auto x)
				{
					// get the current address of where `at` is located
					const std::uint32_t location = p.address + (reinterpret_cast<std::uint32_t>(x) - reinterpret_cast<std::uint32_t>(p.bytes));
					// base the 32-bit relative offset on it
					p.operands[c].rel32 = *reinterpret_cast<std::uint32_t*>(x);

					std::stringstream ss;
					ss << std::setfill('0') << std::setw(8) << std::uppercase << std::hex << (location + sizeof(std::uint32_t) + p.operands[c].rel32);

					p.data += ss.str();

					at += sizeof(std::uint32_t);
				};

				const auto apply_segment_info = [&p]()
				{
					if (p.flags & PRE_SEG_CS) p.data += "cs:";
					if (p.flags & PRE_SEG_DS) p.data += "ds:";
					if (p.flags & PRE_SEG_ES) p.data += "es:";
					if (p.flags & PRE_SEG_SS) p.data += "ss:";
					if (p.flags & PRE_SEG_FS) p.data += "fs:";
					if (p.flags & PRE_SEG_GS) p.data += "gs:";
				};

				std::uint8_t r = prev;

				// grab the basic register initially
				if (prev == mod_byte_not_first)
				{
					r = longreg(*at);
				}

				if (reg_from_opcode_byte)
				{
					r = finalreg(*(at - 1));
				}

				switch (p.operands[c].opmode)
				{
				case disa_optypes::one:
					p.operands[c].disp32 = p.operands[c].disp16 = p.operands[c].disp8 = 1;
					p.data += "1";
					break;
				case disa_optypes::xmm0:
					p.operands[c].append_reg(0);
					p.data += "xmm0";
					p.operands[c].flags |= OP_XMM;
					break;
				case disa_optypes::AL:
					p.operands[c].append_reg(R8_AL);
					p.data += "al";
					p.operands[c].flags |= OP_R8;
					break;
				case disa_optypes::AH:
					p.operands[c].append_reg(R8_AH);
					p.data += "ah";
					p.operands[c].flags |= OP_R8;
					break;
				case disa_optypes::AX:
					p.operands[c].append_reg(R16_AX);
					p.data += "ax";
					p.operands[c].flags |= OP_R16;
					break;
				case disa_optypes::CL:
					p.operands[c].append_reg(R8_CL);
					p.data += "cl";
					p.operands[c].flags |= OP_R8;
					break;
				case disa_optypes::ES:
					p.data += "es";
					break;
				case disa_optypes::SS:
					p.data += "ss";
					break;
				case disa_optypes::DS:
					p.data += "ds";
					break;
				case disa_optypes::GS:
					p.data += "gs";
					break;
				case disa_optypes::FS:
					p.data += "fs";
					break;
				case disa_optypes::EAX:
					p.operands[c].append_reg(R32_EAX);
					p.data += "eax";
					p.operands[c].flags |= OP_R32;
					break;
				case disa_optypes::ECX:
					p.operands[c].append_reg(R32_ECX);
					p.data += "ecx";
					p.operands[c].flags |= OP_R32;
					break;
				case disa_optypes::EBP:
					p.operands[c].append_reg(R32_EBX);
					p.data += "ebp";
					p.operands[c].flags |= OP_R32;
					break;
				case disa_optypes::DRn:
					p.data += mnemonics::dr_names[p.operands[c].append_reg(r)];
					p.operands[c].flags |= OP_DR;
					break;
				case disa_optypes::CRn:
					p.data += mnemonics::cr_names[p.operands[c].append_reg(r)];
					p.operands[c].flags |= OP_CR;
					break;
				case disa_optypes::ST:
					p.data += mnemonics::st_names[p.operands[c].append_reg(0)];
					p.operands[c].flags |= OP_ST;
					break;
				case disa_optypes::Sreg:
					p.data += mnemonics::sreg_names[p.operands[c].append_reg(r)];
					p.operands[c].flags |= OP_SREG;
					break;
				case disa_optypes::mm:
					p.data += mnemonics::mm_names[p.operands[c].append_reg(r)];
					p.operands[c].flags |= OP_MM;
					break;
				case disa_optypes::xmm:
					p.data += mnemonics::xmm_names[p.operands[c].append_reg(r)];
					p.operands[c].flags |= OP_XMM;
					break;
				case disa_optypes::r8:
					p.data += mnemonics::r8_names[p.operands[c].append_reg(r)];
					p.operands[c].flags |= OP_R8;
					break;
				case disa_optypes::r16:
					p.data += mnemonics::r16_names[p.operands[c].append_reg(r)];
					p.operands[c].flags |= OP_R16;
					break;
				case disa_optypes::r16_32:
				case disa_optypes::r32:
					p.data += mnemonics::r32_names[p.operands[c].append_reg(r)];
					p.operands[c].flags |= OP_R32;
					break;
				case disa_optypes::r64:
					p.data += mnemonics::r64_names[p.operands[c].append_reg(r)];
					p.operands[c].flags |= OP_R64;
					break;
				case disa_optypes::m8:
				case disa_optypes::m16:
				case disa_optypes::m16_32:
				case disa_optypes::m32:
				case disa_optypes::m64real:
				case disa_optypes::r_m8:
				case disa_optypes::r_m16:
				case disa_optypes::r_m16_32:
				case disa_optypes::r_m32:
				case disa_optypes::m16_32_and_16_32:
				case disa_optypes::m128:
				case disa_optypes::mm_m64:
				case disa_optypes::xmm_m32:
				case disa_optypes::xmm_m64:
				case disa_optypes::xmm_m128:
				case disa_optypes::STi:
				case disa_optypes::moffs16_32: // segment info applies to this actually
				{
					// Potentially holds a memory offset/pointer?
					// apply segment information...
					apply_segment_info();

					// small edit..
					if (p.operands[c].opmode == disa_optypes::moffs16_32)
					{
						p.data += "[";
						get_imm32(at, true); // changes to a disp32
						p.data += "]";
						break;
					}

					if (c == 0) prev = r;

					r = finalreg(*at);

					switch (*at / 64) // determine mode from `MOD` byte
					{
					case 3:
						switch (p.operands[c].opmode)
						{
						case disa_optypes::r_m8:
						case disa_optypes::m8:
							p.data += mnemonics::r8_names[p.operands[c].append_reg(r)];
							p.operands[c].flags |= OP_R8;
							break;
						case disa_optypes::r_m16:
						case disa_optypes::m16:
							p.data += mnemonics::r16_names[p.operands[c].append_reg(r)];
							p.operands[c].flags |= OP_R16;
							break;
						case disa_optypes::mm_m64:
							p.data += mnemonics::mm_names[p.operands[c].append_reg(r)];
							p.operands[c].flags |= OP_MM;
							break;
						case disa_optypes::xmm_m32:
						case disa_optypes::xmm_m64:
						case disa_optypes::xmm_m128:
						case disa_optypes::m128:
							p.data += mnemonics::xmm_names[p.operands[c].append_reg(r)];
							p.operands[c].flags |= OP_XMM;
							break;
						case disa_optypes::ST:
						case disa_optypes::STi:
							p.data += mnemonics::st_names[p.operands[c].append_reg(r)];
							p.operands[c].flags |= OP_ST;
							break;
						case disa_optypes::CRn:
							p.data += mnemonics::cr_names[p.operands[c].append_reg(r)];
							p.operands[c].flags |= OP_CR;
							break;
						case disa_optypes::DRn:
							p.data += mnemonics::dr_names[p.operands[c].append_reg(r)];
							p.operands[c].flags |= OP_DR;
							break;
						default: // Anything else is going to be 32-bit
							p.data += mnemonics::r32_names[p.operands[c].append_reg(r)];
							p.operands[c].flags |= OP_R32;
							break;
						}
						break;
					case 0:
					{
						p.data += "[";

						switch (r)
						{
						case 4:
							get_sib(0); // Translate SIB byte (no offsets)
							break;
						case 5:
						{
							p.operands[c].disp32 = *reinterpret_cast<std::uint32_t*>(at + 1);
							p.operands[c].flags |= OP_DISP32;

							std::stringstream ss;
							ss << std::setfill('0') << std::setw(8) << std::uppercase << std::hex << p.operands[c].disp32;

							p.data += ss.str();

							at += sizeof(std::uint32_t);
							break;
						}
						default:
							p.data += mnemonics::r32_names[p.operands[c].append_reg(r)];
							p.operands[c].flags |= OP_R32;
							break;
						}

						p.data += "]";
						break;
					}
					case 1:
						p.data += "[";

						if (r == 4)
							get_sib(sizeof(std::uint8_t)); // Translate SIB byte (with BYTE offset)
						else 
						{
							p.data += mnemonics::r32_names[p.operands[c].append_reg(r)];
							p.operands[c].flags |= OP_R32;
							get_imm8(at + 1, false);
						}

						p.data += "]";
						break;
					case 2:
						p.data += "[";

						if (r == 4)
							get_sib(sizeof(std::uint32_t)); // Translate SIB byte (with DWORD offset)
						else 
						{
							p.data += mnemonics::r32_names[p.operands[c].append_reg(r)];
							p.operands[c].flags |= OP_R32;
							get_imm32(at + 1, false);
						}

						p.data += "]";
						break;
					}
					at++;
					break;
				}
				case disa_optypes::imm8:
					get_imm8(at, true); // changes to a disp32
					break;
				case disa_optypes::imm16:
					get_imm16(at, true); // changes to a disp32
					break;
				case disa_optypes::imm16_32:
				case disa_optypes::imm32:
					get_imm32(at, true); // changes to a disp32
					break;
				case disa_optypes::moffs8:
					p.data += "[";
					get_imm32(at, true); // changes to a disp32
					p.data += "]";
					break;
				case disa_optypes::rel8:
					get_rel8(at);
					break;
				case disa_optypes::rel16:
					get_rel16(at);
					break;
				case disa_optypes::rel16_32:
				case disa_optypes::rel32:
					get_rel32(at);
					break;
				case disa_optypes::ptr16_32:
					get_imm32(at, true);
					p.data += ":";
					get_imm16(at, true);
					break;
				}

				// move up to the next operand
				if (c < noperands - 1 && noperands > 1)
				{
					p.data += ",";
				}
			}

			break;
		}
	}

	p.len = reinterpret_cast<std::size_t>(at) - reinterpret_cast<std::size_t>(p.bytes);

	if (p.len == 0)
	{
		p.len = 1;
		p.data = "???";
	}

	return p;
}

std::vector<disa_inst> disa_read(const std::uintptr_t address, const std::size_t count)
{
	std::uintptr_t at = address;
	std::vector<disa_inst> inst_list = { };

	for (std::size_t c = 0; c < count; c++)
	{
		const auto i = read(at);
		inst_list.push_back(i);
		at += i.len;
	}

	return inst_list;
}

std::vector<disa_inst> disa_ranged_read(const std::uintptr_t from, const std::uintptr_t to)
{
	std::uintptr_t at = from;
	std::vector<disa_inst> inst_list = { };

	while (at < to)
	{
		const auto i = read(at);
		inst_list.push_back(i);
		at += i.len;
	}

	return inst_list;
}




