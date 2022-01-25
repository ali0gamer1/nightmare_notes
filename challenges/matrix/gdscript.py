import gdb

def get(index): #get from space (0x7fffffffe5f0)
    val = gdb.execute(f"x/z {0x7fffffffe5f0 + index * 8}", to_string = True)
    val = (val.split(":")[1].strip())
    return val

#pc = get(1)
#opcodes = get(0)
#space1 = get(2)
#space2 = get(3)

break1 = str(0x5555555555c2)
gdb.execute("b *" + break1 + "\nr\n")
f = 0
flag = True
while flag:
    
