#include "../disa.hpp"

std::vector<std::uint8_t> place_trampoline(const std::uintptr_t address_from, const std::uintptr_t address_to, std::uintptr_t location_jmpback, const bool copy_old_bytes = false);
std::vector<std::uint8_t> place_hook(const std::uintptr_t address_from, const std::uintptr_t address_to);
