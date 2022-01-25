import gdb
import re

shuff_map = [ 0x02, 0x06, 0x07, 0x01, 0x05, 0x0b, 0x09, 0x0e, 0x03, 0x0f, 0x04, 0x08, 0x0a, 0x0c, 0x0d, 0x00 ]

peda = PEDA()
shuff_dic = {}
for i, a in enumerate(shuff_map):
    shuff_dic[a] = i

flag = list("CTF{0123456789}\x00")
known_indexes = [0,1,2,3,14,15]

gdb.execute("b *main + 87")
while len(known_indexes) != len(flag):
    
    tmp = ''.join(flag[:-1:])
    gdb.execute(f"r <<<{tmp}")
    output = gdb.execute("info register xmm0", to_string = True)
    xmm0 = re.search(r"v16_int8 = \{(.*)\}", output).groups()[0]
    xmm0 = eval("[" + xmm0 + "]")
    timp = []
    for i in known_indexes:
        app_index = shuff_dic[i]
        if app_index not in known_indexes:
            flag[app_index] = chr(xmm0[app_index])
            timp.append(app_index)
    known_indexes.extend(timp)
print(''.join(flag[:-1:]))


