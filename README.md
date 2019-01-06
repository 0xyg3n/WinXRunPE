# WinXRunPE x86 x64
This is a RunPE that can inject 32-bit executables into 32-bit processes. And 64-bit executables into 64-bit executables. The 32-bit edition actually runs on 64-bit compiled executables. So no more forced to target 32-bit when using RunPE.

I'd be glad if you collaborated with me on this project. So fork it today!

# To be done
- Relocations. If VirtualAllocEx() fails to allocate data in the imagebase specified, then we need to allocate what memory we can get, and apply relocations.
( There is a working demo here: https://github.com/hasherezade/demos/blob/master/run_pe/src/runpe.h but it's written in C )