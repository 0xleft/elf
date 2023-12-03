gcc -shared -fPIC ldkit.c -o ldkit.so -Idl -I../include/syscall.h
gcc -static -fPIC elf.c -o elf -lcurl