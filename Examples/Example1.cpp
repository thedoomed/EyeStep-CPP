#include <Windows.h>
#include <iostream>
#include "disasm.hpp"

void my_function()
{
	printf("Example...\n");
	printf("DISA is hot\n");
}

int main()
{
	SetConsoleTitleA("DISA Example");
	disa_load();

	for (const auto& i : disa_read(reinterpret_cast<std::uintptr_t>(&my_function), 8))
	{
		std::cout << i.data << std::endl;
	}

	return std::cin.get();
}