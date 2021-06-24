#include <Windows.h>
#include <iostream>
#include "DISA/disa.hpp"

void my_function()
{
	printf("Example...\n");
	printf("DISA is good\n");
	int i = 3;
	printf("%i\n", i);
}

int main()
{
	SetConsoleTitleA("DISA Example");
	disa_load();

	// Read the first 8 instructions in our function `my_function`
	for (const auto& i : disa_read(reinterpret_cast<std::uintptr_t>(&my_function), 12))
	{
		std::cout << i.data << std::endl;
	}

	return std::cin.get();
}
