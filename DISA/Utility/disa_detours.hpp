#include "../disa.hpp"

struct detour_results
{
	std::vector<std::uintptr_t>reg_contents;
	std::uintptr_t reg;
};

class disa_detour
{
private:
	std::vector<std::uint8_t>old_bytes;
	std::uintptr_t jmpback;
	std::size_t dumpsize;
	std::size_t maxhits;
	std::uint8_t debug_reg32;
	std::uint32_t reg_offset;
	std::uint32_t timeout;
	std::uintptr_t current_hook;
public:
	disa_detour();
	~disa_detour();

	std::uintptr_t address;
	detour_results result; // applies only to the specified register

	void set_reg32(std::uint8_t reg32);
	void set_reg_offset(std::uint32_t offset); // offset from the register to dump
	void set_dump_size(std::size_t count); // total number of offsets to dump from the register
	void set_hit_count(std::size_t count); // total number of times the hook can be used before returning (if suspend is set to true)
	void set_timeout(std::uint32_t ms); // total number of times the hook can be used before returning (if suspend is set to true)
	bool start(bool suspend = false);
	void stop();
};
