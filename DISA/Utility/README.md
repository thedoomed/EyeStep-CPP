# Debugging Registers with DISA

The goal of this api is to provide the most versatile detouring functionality yet.
Using an automated trampoline hook, you have maximum control over which registers you wish to view and identify.

```
disa_debug dbg(0x15E5AA0); // location of the hook/address to debug
dbg.set_dump_size(1); // number of offsets of EBP to debug (1) ***
dbg.set_reg32(R32_EBP); // 32-bit register to debug
dbg.set_reg_offset(8); // starting offset (from EBP)
dbg.start();

// *** if this is greater than 1, it will keep dumping the next offset (+4) from the register
// So if this is 3, it will dump [ebp+8], [ebp+C], [ebp+10], into 'dbg.result.reg_contents'
```

The above example will wait until the instruction at 0x15E5AA0 is executed.
As soon as its executed, it will grab 1 offset from EBP, starting at 8.<br>
So essentially, it reads whatever value is contained in [ebp+8], in the instruction located at 0x15E5AA0.<br>
Once the debug hits, it will return from dbg.start() and you can access the results.<br>

To view the results:
```
std::cout << "Result: " << std::hex << dbg.result.reg_contents.front() << std::endl;
std::cout << "EBP: " << std::hex << dbg.result.reg << std::endl;
```

This is the least of its capabilities.<br>
Let's say you want to execute code while its waiting for the instruction to be executed.<br>

Simply pass `false` as an arg to dbg.start, and it wont suspend the current thread or wait for results.
It's up to you when you want to break it.
Call dbg.stop() when you want to stop the debug, and then you can view the latest results.<br>

This is useful if you want to run code that will invoke execution at the instruction.






