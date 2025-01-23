import angr
import claripy

binary_path = "crackme100"
proj = angr.Project(binary_path)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x00401378, avoid = 0x00401389) 

if simgr.found:
	found_state = simgr.found[0]
	print("Found a path to the target address:", simgr.found[0].posix.dumps(0))
