#pragma once
#include <cstdint>
#include <string>
#include <vector>

// basic filters
constexpr std::uint32_t OP_NONE				= 0x00000000;
constexpr std::uint32_t OP_SINGLE			= 0x00000001;
constexpr std::uint32_t OP_SRC_DEST			= 0x00000002;
constexpr std::uint32_t OP_EXTENDED			= 0x00000004;
constexpr std::uint32_t OP_IMM8				= 0x00000010;
constexpr std::uint32_t OP_IMM16			= 0x00000020;
constexpr std::uint32_t OP_IMM32			= 0x00000040;
constexpr std::uint32_t OP_DISP8			= 0x00000080;
constexpr std::uint32_t OP_DISP16			= 0x00000100;
constexpr std::uint32_t OP_DISP32			= 0x00000200;
constexpr std::uint32_t OP_R8				= 0x00000400; 
constexpr std::uint32_t OP_R16				= 0x00000800; 
constexpr std::uint32_t OP_R32				= 0x00001000; 
constexpr std::uint32_t OP_R64				= 0x00002000; 
constexpr std::uint32_t OP_XMM				= 0x00004000; 
constexpr std::uint32_t OP_MM				= 0x00008000; 
constexpr std::uint32_t OP_ST				= 0x00010000; 
constexpr std::uint32_t OP_SREG				= 0x00020000; 
constexpr std::uint32_t OP_DR				= 0x00040000; 
constexpr std::uint32_t OP_CR				= 0x00080000; 

const enum : std::uint8_t
{
	R8_AL,
	R8_CL,
	R8_DL,
	R8_BL,
	R8_AH,
	R8_CH,
	R8_DH,
	R8_BH,
};

const enum : std::uint8_t
{
	R16_AX,
	R16_CX,
	R16_DX,
	R16_BX,
	R16_SP,
	R16_BP,
	R16_SI,
	R16_DI,
};

const enum : std::uint8_t
{
	R32_EAX,
	R32_ECX,
	R32_EDX,
	R32_EBX,
	R32_ESP,
	R32_EBP,
	R32_ESI,
	R32_EDI,
};

struct disa_opinfo
{
	std::string code;
	std::string opcode_name;
	std::vector<std::uint8_t> operands;
	std::string description;
};

class disa_operand
{
private:
	std::uint8_t n_reg;
public:
	disa_operand();
	~disa_operand();

	std::uint32_t flags;
	std::uint8_t opmode;
	std::vector<std::uint8_t> reg;
	std::uint8_t mul; // single multiplier

	std::uint8_t append_reg(const std::uint8_t reg_type);

	union
	{
		std::uint8_t rel8;
		std::uint16_t rel16;
		std::uint32_t rel32;
	};

	union
	{
		std::uint8_t imm8;
		std::uint16_t imm16;
		std::uint32_t imm32;
	};

	union
	{
		std::uint8_t disp8;
		std::uint16_t disp16;
		std::uint32_t disp32;
	};
};

class disa_inst
{
public:
	disa_inst();
	~disa_inst();

	std::string data;
	disa_opinfo info;

	std::uint32_t flags;
	std::uint8_t bytes[16];
	std::uintptr_t address;
	std::size_t len;

	std::vector<disa_operand>operands;

	disa_operand src();
	disa_operand dest();
};

bool disa_load();

std::vector<disa_inst> disa_read(const std::uintptr_t address, const size_t count = 1);
std::vector<disa_inst> disa_ranged_read(const std::uintptr_t address_from, const std::uintptr_t address_to);


