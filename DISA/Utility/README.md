# Debugging Registers with DISA

The goal of this api is to provide the most versatile detouring functionality yet.
Using an automated trampoline hook, you have maximum control over which registers you wish to view and identify.

```
disa_debug dbg(aslr(0x15E5AA0)); // location of the hook/address to debug
dbg.set_dump_size(1); // number of offsets of EBP to debug (1) ***
dbg.set_reg32(R32_EBP); // 32-bit register to debug
dbg.set_reg_offset(8); // starting offset (from EBP)
dbg.start();

// *** if this is greater than 1, it will keep dumping the next offset (+4) from the register
// So if this is 3, it will dump [ebp+8], [ebp+C], [ebp+10], into 'dbg.result.reg_contents'
```

The above example will grab 1 offset from EBP, starting at +8 once the address is executed<br>
It essentially reads whatever value is currently contained in [ebp+8]<br> 
at the address 0x15E5AA0.

To view the results:
```
std::cout << "Result: " << std::hex << dbg.result.reg_contents.front() << std::endl;
std::cout << "EBP: " << std::hex << dbg.result.reg << std::endl;
```




