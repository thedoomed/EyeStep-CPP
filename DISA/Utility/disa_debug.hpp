#include "../disa.hpp"

struct disa_debug_results
{
	std::vector<std::uintptr_t>reg_contents;
	std::uintptr_t reg;
};

class disa_debug
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
	disa_debug();
	disa_debug(const std::uintptr_t);
	~disa_debug();

	std::uintptr_t address;
	disa_debug_results result; // applies only to the specified register

	void set_address(const std::uintptr_t location);
	void set_reg32(const std::uint8_t reg32);
	void set_reg_offset(const std::uint32_t offset); // offset from the register to dump
	void set_dump_size(const std::size_t count); // total number of offsets to dump from the register
	void set_hit_count(const std::size_t count); // total number of times the hook can be used before returning (if suspend is set to true)
	void set_timeout(const std::uint32_t ms); // total number of times the hook can be used before returning (if suspend is set to true)
	bool start(const bool suspend = true);
	void stop(void);
};
