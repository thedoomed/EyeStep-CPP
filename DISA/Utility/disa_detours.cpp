#include <Windows.h>
#include "disa_detours.hpp"

disa_detour::disa_detour()
{
	dumpsize = 0;
	maxhits = 1;
	debug_reg32;
	std::uint32_t reg_offset;
}

disa_detour::~disa_detour()
{
}

void disa_detour::set_reg32(std::uint8_t reg32)
{
	debug_reg32 = reg32;
}

void disa_detour::set_reg_offset(std::uint32_t offset)
{
	reg_offset = offset;
}

void disa_detour::set_dump_size(std::size_t count)
{
	dumpsize = count;
}

void disa_detour::set_hit_count(std::size_t count)
{
	maxhits = count;
}

static std::vector<std::uint8_t> place_hook(const std::uintptr_t address_from, const std::uintptr_t address_to)
{
	std::vector<std::uint8_t>old_bytes = {};

	std::size_t size = 0;
	while (size < 5)
	{
		size += disa_read(address_from).front().len; // calculate number of nops
	}

	memcpy(old_bytes.data(), reinterpret_cast<void*>(address_from), size);


	DWORD old;
	VirtualProtect(reinterpret_cast<void*>(address_from), size, PAGE_EXECUTE_READWRITE, &old);

	*reinterpret_cast<std::uint8_t*>(address_from) = 0xE9;
	*reinterpret_cast<std::uint32_t*>(address_from + 1) = (address_to - address_from) - 5;

	for (std::size_t i = 5; i < size; i++)
	{
		*reinterpret_cast<std::uint8_t*>(address_from + i) = 0x90;
	}

	VirtualProtect(reinterpret_cast<void*>(address_from), size, old, &old);


	return old_bytes;
}

static std::vector<std::uint8_t> place_trampoline(const std::uintptr_t address_from, const std::uintptr_t address_to, std::uintptr_t location_jmpback, bool copy_old_bytes = false)
{
	std::vector<std::uint8_t>old_bytes = {};

	std::size_t size = 0;
	while (size < 5)
	{
		size += disa_read(address_from).front().len; // calculate extra nops
	}

	// store the old bytes
	memcpy(old_bytes.data(), reinterpret_cast<void*>(address_from), size);

	if (copy_old_bytes)
	{
		// copy old bytes into the hook, so that they
		// still get executed before it jumps back
		memcpy(reinterpret_cast<void*>(location_jmpback), reinterpret_cast<void*>(address_from), size);
		location_jmpback += size;
	}

	// place the trampoline jmpback
	*reinterpret_cast<std::uint8_t*>(location_jmpback) = 0xE9;
	*reinterpret_cast<std::uint32_t*>(location_jmpback + 1) = (address_from - location_jmpback) - 5;

	DWORD old;
	VirtualProtect(reinterpret_cast<void*>(address_from), size, PAGE_EXECUTE_READWRITE, &old);

	// place the hook
	*reinterpret_cast<std::uint8_t*>(address_from) = 0xE9;
	*reinterpret_cast<std::uint32_t*>(address_from + 1) = (address_to - address_from) - 5;

	for (std::size_t i = 5; i < size; i++)
	{
		*reinterpret_cast<std::uint8_t*>(address_from + i) = 0x90;
	}

	VirtualProtect(reinterpret_cast<void*>(address_from), size, old, &old);


	return old_bytes;
}

bool disa_detour::start(bool suspend)
{
	if (current_hook) return false;

	const auto hook = reinterpret_cast<std::uint8_t*>(VirtualAlloc(nullptr, 256, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	if (!hook)
	{
		return false;
	}

	current_hook = reinterpret_cast<std::uintptr_t>(hook);

	std::size_t size = 0;


	const auto r1 = (debug_reg32 != R32_ESI) ? R32_ESI : R32_EAX;
	const auto r2 = (debug_reg32 != R32_EDI) ? R32_EDI : R32_EAX;

	hook[size++] = 0x50 + r1; // push eax
	hook[size++] = 0x50 + r2; // push edi

	// set the starting offset, from the register
	// 
	hook[size++] = 0xB8 + r2; // mov edi, reg_offset

	*reinterpret_cast<uint32_t*>(hook + size) = reg_offset;
	size += sizeof(uint32_t);


	// if the requested number of executions has been reached,
	// stop here and DO NOT continue the hook
	// 
	hook[size++] = 0x81; // add [hit_count], 1
	hook[size++] = 0x05;

	*reinterpret_cast<std::uint8_t**>(hook + size) = hook + 248;
	size += sizeof(std::uint8_t*);

	*reinterpret_cast<int*>(hook + size) = 1;
	size += sizeof(int);


	hook[size++] = 0x81; // cmp [hit_count], maxhits
	hook[size++] = 0x3D;
	*reinterpret_cast<std::uint8_t**>(hook + size) = hook + 248;
	size += sizeof(std::uint8_t*);

	*reinterpret_cast<std::size_t*>(hook + size) = maxhits;
	size += sizeof(std::size_t);


	hook[size++] = 0x77; // ja next
	
	if (dumpsize > 0)
	{
		hook[size++] = 0x1E;
	}
	else
	{
		hook[size++] = 0x0A;
	}

	// [LABEL]
	// dump_next_register:
	// 
	
	// place the actual value of the register (the memory address it points to)
	// into our holder location
	hook[size++] = 0x89; // mov [actual reg value],debug_reg32
	hook[size++] = 5 + (debug_reg32 * 8);

	*reinterpret_cast<std::uint8_t**>(hook + size) = hook + 252;
	size += sizeof(std::uint8_t*);


	// if dumpsize is set, this will dump the contents
	// inside the register up to dumpsize * 4.
	// the results are appended to `detour_results.reg_contents`
	if (dumpsize > 0)
	{
		hook[size++] = 0x8B; // mov eax,[debug_reg32+edi+00]
		hook[size++] = 0x44 + (r1 * 8);
		hook[size++] = 0x00 + (r2 * 8) + debug_reg32;
		hook[size++] = 0x00;

		hook[size++] = 0x89; // mov [edi+OUTPUT_LOCATION],eax
		hook[size++] = 0x80 + r2;

		*reinterpret_cast<std::uint8_t**>(hook + size) = hook + 256;
		size += sizeof(std::uint8_t*);


		hook[size++] = 0x81; // add edi, 4
		hook[size++] = 0xC0 + r2;

		*reinterpret_cast<int*>(hook + size) = 4;
		size += sizeof(int);


		hook[size++] = 0x81; // cmp edi, dumpsize
		hook[size++] = 0xF8 + r2;

		*reinterpret_cast<std::size_t*>(hook + size) = dumpsize * sizeof(std::uintptr_t);
		size += sizeof(std::size_t);


		hook[size++] = 0x72; // jb dump_next_register
		hook[size++] = 0xE2;
	}


	// [LABEL]
	// next:
	//
	hook[size++] = 0x58 + r2; // pop edi
	hook[size++] = 0x58 + r1; // pop eax

	old_bytes = place_trampoline(address, current_hook, current_hook + size, true);

	if (suspend)
	{
		std::size_t hits = 0;

		while (hits < maxhits)
		{
			hits = *reinterpret_cast<size_t*>(current_hook + 248);
			Sleep(10);
		}

		stop();
	}

	return true;
}

void disa_detour::stop()
{
	result = detour_results();

	if (current_hook && address)
	{
		// read out the current register values into the results

		const std::uintptr_t output_reg = *reinterpret_cast<uintptr_t*>(current_hook + 252);
		const std::uintptr_t* output_reg_contents = reinterpret_cast<uintptr_t*>(current_hook + 256);
		
		for (std::size_t i = 0; i < dumpsize; i++)
		{
			result.reg_contents.push_back(output_reg_contents[i]);
		}

		result.reg = output_reg;

		DWORD old;

		VirtualProtect(reinterpret_cast<void*>(address), old_bytes.size(), PAGE_EXECUTE_READWRITE, &old);
		memcpy(reinterpret_cast<void*>(address), old_bytes.data(), old_bytes.size());
		VirtualProtect(reinterpret_cast<void*>(address), old_bytes.size(), old, &old);

		VirtualFree(reinterpret_cast<void*>(current_hook), 0, MEM_RELEASE);
	}

	current_hook = 0;
	address = 0;
	old_bytes.clear();
}


