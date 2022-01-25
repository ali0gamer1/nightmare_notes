
find_addr  = 0x01011cc # SUCCESS
avoid_addr = 0x01011a6 # FAILURE
base_addr = 0x0100000

import angr

# Establish the Angr Project
target = angr.Project("./matrix", main_opts = {"base_addr" : base_addr})

# Specify the desired address which means we have the correct input
desired_adr = 0x01011cc

# Specify the address which if it executes means we don't have the correct input
wrong_adr = 0x01011a6

# Establish the entry state
entry_state = target.factory.entry_state(args=["./matrix"])

# Establish the simulation
simulation = target.factory.simulation_manager(entry_state)

# Start the simulation
simulation.explore(find = desired_adr, avoid = wrong_adr)

solution = simulation.found[0].posix.dumps(0)
print solution

