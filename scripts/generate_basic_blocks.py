#!/usr/bin/env python3
import angr
import time
import sys

def main():
	if len(sys.argv) < 3:
		print("usage: %s elf_path output_path" % sys.argv[0])
		sys.exit(-1)

	elf_path = sys.argv[1]
	output_path = sys.argv[2]
	with open(output_path, "w") as f:
		print("Creating file '%s' from '%s'" % (output_path, elf_path))
		project = angr.Project(
			elf_path,
			load_options={'auto_load_libs': False},
			main_opts={'base_addr': 0},
		)

		t = time.time()
		cfg = project.analyses.CFGFast()
		print("Calculated cfg_fast in %.2f seconds" % (time.time() - t))
		count = 0
		for node in cfg.graph.nodes():
			if (node.block):
				f.write(hex(node.block.addr) + "\n")
				count += 1
		print("Written", count, "basic blocks in", output_path)

if __name__ == "__main__":
	main()
