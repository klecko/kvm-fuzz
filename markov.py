#!/usr/bin/env python3
import sys
import math
from pathlib import Path
from collections import defaultdict
import networkx as nx
# import matplotlib.pyplot as plt


dir = Path("traces")

first_syscall = None
first_syscall_filename = None
traces = []
for filename in dir.iterdir():
	with open(filename) as f:
		trace = f.readlines()
		if not trace:
			continue
		trace = [(line.split()[0], int(line.split()[1])) for line in trace]

		# Check last syscall
		if trace[-1][0] != "exit_group":
			print(f"Warning: trace '{filename}' has '{trace[-1][0]}' as last syscall, ignoring")
			continue

		# Check first syscall
		if not first_syscall:
			first_syscall = trace[0][0]
			first_syscall_filename = filename
		if trace[0][0] != first_syscall:
			print(f"Not every trace starts with the same syscall: file '{first_syscall_filename}' " +
			      f"starts with '{first_syscall}', file '{filename}' starts with '{trace[0][0]}'. Aborting.")
			exit()

		traces.append(trace)


# get syscalls instructions
syscalls_instructions = defaultdict(list)
for trace in traces:
	for line in trace:
		syscalls_instructions[line[0]].append(line[1])
syscalls_total_instructions = {
	syscall: sum(instructions) for syscall, instructions in syscalls_instructions.items()
}
syscalls_avg_instructions = {
	syscall: sum(instructions)/len(instructions) for syscall, instructions in syscalls_instructions.items()
}

# get probability of successors
successors = defaultdict(list)
for trace in traces:
	trace = [line[0] for line in trace] # get only names
	for i in range(1, len(trace)):
		successors[trace[i-1]].append(trace[i])
successors["exit_group"] = []

successors_probs = {syscall: dict() for syscall in successors.keys()}
for syscall, succs in successors.items():
	for succ in set(succs):
		successors_probs[syscall][succ] = succs.count(succ)/len(succs)


# calculate avg number of instructions
def avg_instructions():
	import z3
	avg_instr_from_syscalls = {syscall: z3.Real(f"avg_instr_from_{syscall}") for syscall in syscalls_instructions.keys()}
	s = z3.Solver()

	for syscall, succs_probs in successors_probs.items():
		val = sum([avg_instr_from_syscalls[succ]*prob for succ, prob in succs_probs.items()])
		ec = avg_instr_from_syscalls[syscall] == val + syscalls_avg_instructions[syscall]
		s.add(ec)

	assert s.check() == z3.sat
	m = s.model()
	first_syscall = traces[0][0][0]
	result = m[avg_instr_from_syscalls[first_syscall]]
	return result.numerator().as_long() / result.denominator().as_long()


# print(avg_instructions_from_syscall(traces[0][0][0]))
instr_count = [sum([line[1] for line in trace]) for trace in traces]
result_real = sum(instr_count)/len(instr_count)
result_calculated = avg_instructions()

print("calculated:", result_calculated)
print("real:", result_real)
print(f"calculated is {100*(result_calculated - result_real)/result_real:.4f}% more than real")





print()


# drawing stuff
g = nx.DiGraph()

max_avg_instructions = max(syscalls_avg_instructions.values())
for syscall, avg_instructions in syscalls_avg_instructions.items():
	# red_intensity = int(avg_instructions*0xff/max_avg_instructions)
	if avg_instructions == 0: avg_instructions = 1
	red_intensity = int(math.log(avg_instructions)*0xff/math.log(max_avg_instructions))
	g.add_node(syscall, color=f"#{red_intensity:02x}0000", penwidth=4)
# print(syscalls_avg_instructions)

# max_total_instructions = max(syscalls_total_instructions.values())
# for syscall, total_instructions in syscalls_total_instructions.items():
# 	# red_intensity = int(total_instructions*0xff/max_total_instructions)
# 	if total_instructions == 0: total_instructions = 1
# 	red_intensity = int(math.log(total_instructions)*0xff/math.log(max_total_instructions))
# 	g.add_node(syscall, color=f"#{red_intensity:02x}0000", penwidth=4)
# print(syscalls_total_instructions)


for syscall, succs_probs in successors_probs.items():
	for succ, prob in succs_probs.items():
		g.add_edge(syscall, succ, label=f"{prob:.2f}")


# g.nodes["write"]["fillcolor"] = "red"
a = nx.nx_agraph.to_agraph(g)
a.layout("dot")
a.draw("output.png")



# pos = nx.spring_layout(g, seed=7)
# # pos = nx.nx_agraph.graphviz_layout(g)
# # nodes
# # nx.draw_networkx_nodes(g, pos, node_size=700)
# nx.draw_networkx_nodes(g, pos, node_size=[200+len(node)*400 for node in g.nodes()])

# # edges
# nx.draw_networkx_edges(g, pos)
# # nx.draw_networkx_edges(g, pos, edgelist=elarge, width=6)
# # nx.draw_networkx_edges(
# #     g, pos, edgelist=esmall, width=6, alpha=0.5, edge_color="b", style="dashed"
# # )

# # node labels
# nx.draw_networkx_labels(g, pos)#, font_size=20, font_family="sans-serif")
# # edge weight labels
# edge_labels = {(u, v): f'{d["weight"]:.2f}' for u, v, d in g.edges(data=True)}
# nx.draw_networkx_edge_labels(g, pos, edge_labels)

# ax = plt.gca()
# ax.margins(0.08)
# plt.axis("off")
# plt.tight_layout()
# plt.show()