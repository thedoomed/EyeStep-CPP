#include "easy_hooks.hpp"
#include <Windows.h>

std::vector<std::uint8_t> place_hook(const std::uintptr_t address_from, const std::uintptr_t address_to)
{
	std::vector<std::uint8_t>old_bytes = {};

	std::size_t size = 0;
	while (size < 5)
	{
		size += disa_read(address_from + size).front().len; // calculate number of nops
	}

	std::memcpy(old_bytes.data(), reinterpret_cast<void*>(address_from), size);


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

std::vector<std::uint8_t> place_trampoline(const std::uintptr_t address_from, const std::uintptr_t address_to, std::uintptr_t location_jmpback, const bool copy_old_bytes)
{
	std::size_t size = 0;

	while (size < 5)
	{
		size += disa_read(address_from + size).front().len;
	}

	std::vector<std::uint8_t>old_bytes;
	old_bytes.resize(size);

	// store the old bytes
	std::memcpy(&old_bytes[0], reinterpret_cast<void*>(address_from), size);

	if (copy_old_bytes)
	{
		// copy old bytes into the hook, so that they
		// still get executed before it jumps back
		std::memcpy(reinterpret_cast<void*>(location_jmpback), reinterpret_cast<void*>(address_from), size);
		location_jmpback += size;
	}

	// place the trampoline jmpback
	*reinterpret_cast<std::uint8_t*>(location_jmpback) = 0xE9;
	*reinterpret_cast<std::uint32_t*>(location_jmpback + 1) = (address_from - location_jmpback);

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
