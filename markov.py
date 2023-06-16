#!/usr/bin/env python3
import sys
import math
from pathlib import Path
from collections import defaultdict
import networkx as nx
# import matplotlib.pyplot as plt

class TracingType:
	User = 0
	Kernel = 1


def read_traces(dir_path):
	dir = Path(dir_path)
	tracing_type = None
	first_state = None
	first_state_filename = None
	last_state = None
	last_state_filename = None
	traces = []
	for filename in dir.iterdir():
		with open(filename) as f:
			trace = f.readlines()
			if not trace:
				continue

			if tracing_type == None:
				if "+" in trace[0].split()[1]:
					tracing_type = TracingType.User
				else:
					tracing_type = TracingType.Kernel

			trace = [(" ".join(line.split()[:-1]), int(line.split()[-1])) for line in trace]

			# Check last state. We want to warn when traces have different last state,
			# which may be due to the run crashing, time-outing, or being incomplete
			# (the program was interrupted while writing it to disk).
			if not last_state:
				last_state = trace[-1][0]
				last_state_filename = filename
			if trace[-1][0] != last_state:
				print(f"Warning: trace '{filename}' has '{trace[-1][0]}' as last state, while " +
					f"trace '{last_state_filename}' ends with '{last_state}'.")

			# Check first state. We require every trace to start at the same point.
			if not first_state:
				first_state = trace[0][0]
				first_state_filename = filename
			if trace[0][0] != first_state:
				print(f"Not every trace starts with the same state: file '{first_state_filename}' " +
					f"starts with '{first_state}', file '{filename}' starts with '{trace[0][0]}'. Aborting.")
				exit()

			traces.append(trace)
	return traces

print("Reading traces")
traces = read_traces("./traces")
print(f"Read {len(traces)} traces")

# get states instructions
states_instructions = defaultdict(list)
for trace in traces:
	for line in trace:
		states_instructions[line[0]].append(line[1])
states_total_instructions = {
	state: sum(instructions) for state, instructions in states_instructions.items()
}
states_avg_instructions = {
	state: sum(instructions)/len(instructions) for state, instructions in states_instructions.items()
}

# get probability of successors
successors = {state:[] for state in states_total_instructions}
for trace in traces:
	trace = [line[0] for line in trace] # get only names
	for i in range(1, len(trace)):
		successors[trace[i-1]].append(trace[i])
	successors[trace[-1]].append(None)

successors_probs = {state: dict() for state in successors.keys()}
for state, succs in successors.items():
	for succ in set(succs):
		successors_probs[state][succ] = succs.count(succ)/len(succs)


# calculate avg number of instructions
def avg_instructions():
	import z3
	avg_instr_from_states = {state: z3.Real(f"avg_instr_from_{state}") for state in states_instructions.keys()}
	s = z3.Solver()

	for state, succs_probs in successors_probs.items():
		val = sum([avg_instr_from_states[succ]*prob for succ, prob in succs_probs.items() if succ])
		ec = avg_instr_from_states[state] == val + states_avg_instructions[state]
		s.add(ec)

	assert s.check() == z3.sat
	m = s.model()
	first_state = traces[0][0][0]
	result = m[avg_instr_from_states[first_state]]
	return result.numerator().as_long() / result.denominator().as_long()


# print(avg_instructions_from_state(traces[0][0][0]))
instr_count = [sum([line[1] for line in trace]) for trace in traces]
result_real = sum(instr_count)/len(instr_count)
result_calculated = avg_instructions()
# result_calculated = 1

print("calculated:", result_calculated)
print("real:", result_real)
print(f"calculated is {100*(result_calculated - result_real)/result_real:.4f}% more than real")





# drawing stuff
g = nx.DiGraph()

max_avg_instructions = max(states_avg_instructions.values())
for state, avg_instructions in states_avg_instructions.items():
	# red_intensity = int(avg_instructions*0xff/max_avg_instructions)
	if avg_instructions == 0: avg_instructions = 1
	red_intensity = int(math.log(avg_instructions)*0xff/math.log(max_avg_instructions))
	g.add_node(state, color=f"#{red_intensity:02x}0000", penwidth=4)
# print(states_avg_instructions)

# max_total_instructions = max(states_total_instructions.values())
# for state, total_instructions in states_total_instructions.items():
# 	# red_intensity = int(total_instructions*0xff/max_total_instructions)
# 	if total_instructions == 0: total_instructions = 1
# 	red_intensity = int(math.log(total_instructions)*0xff/math.log(max_total_instructions))
# 	g.add_node(state, color=f"#{red_intensity:02x}0000", penwidth=4)
# print(states_total_instructions)


for state, succs_probs in successors_probs.items():
	for succ, prob in succs_probs.items():
		if succ:
			g.add_edge(state, succ, label=f"{prob:.8f}")


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