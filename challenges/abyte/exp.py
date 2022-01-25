from z3 import *

z = Solver()
inp = []
for i in range(0x21):
    inp.append(BitVec("%s" % i, 8))

z.add(inp[-1] == 0xa)
