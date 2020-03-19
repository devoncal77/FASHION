# Note: As of 07/30/2019, this python file only runs on acyclic graphs
# To be able to run analysis on cyclic graphs, refer to Algorithms 4, 5, 6 from 
# the paper

import string
import itertools
import sys


# Global tables to store values for each node.

chi_n_table = []
prob_table = [1.0, None]
delta_n_table = []
Gm = []

#These tables for testing only
#prob_table2 = [1.0, 1.0, 0.75, 0.75]
#delta_n_table2 = [[], [1], [1], [1]]
#chi_n_table2 = [[0, []], [1, [1]], [2, [1]], [3, [1]]]	

cond_prob_table = [None] * 2

def main():
		global Gm
		global prob_table
		input_file = "input.P"
		node_file = "VERTICES.CSV"
		edge_file = "ARCS.CSV"
		list_vuls(input_file)
		All_nodes = define_nodes(node_file)
		nodes = All_nodes[0]
		LEAF_nodes = All_nodes[1]
		num_nodes = max(nodes[0] + LEAF_nodes)
		edges = define_edges(edge_file, nodes[0])
		Gm = integrate_cvss("vulnerabilities.txt", node_file, edge_file, nodes)
		cumulative_metric(nodes, edges)
		while len(prob_table) <= num_nodes:
			prob_table.append(None)
		for i in range(1, len(prob_table)):
			if prob_table[i] == None:
				prob_table[i] = "Node " + str(i) + ": " + "leaf"
				print(prob_table[i])
				#print("\n")
			else:
				prob_table[i] = "Node " + str(i) + ": " + str(prob_table[i])
				print(prob_table[i])
				#print("\n")
	
# Opens the input.P file and looks for the lines with the clause cvss(VUL_NAME, COMPLEXITY)
# and stores them in a text file
def list_vuls(file):
	file_object = open(file)
	boo = 0
	vul_list = []
	f = open("vulnerabilities.txt", "w+")
	for line in file_object:
		if "cvss(" in line:
			boo = 1
			line = line.strip('cvss(')
			line = line.replace(').','')
			line = line.replace(',', ' ')
			line = line.replace("'", "")
			f.write(line)
			f.write("\n")
	f.seek(0)
	for line in f:
		single_vul = line.split()
		if single_vul != []:
			vul_list.append(single_vul)	
	f.close()
	if boo:
		return vul_list
	else:
		return None

# Takes info from multiple files to link vulnerabilities to the right AND nodes as well as storing probability based on cvss complexity score
# Gm[n] = ['Prob of node n']
# If the node is not an attack step node or it the attack step node is not connected to 
# a leaf node detailing a vulnerability, Gm[n] is set to 1.0

def integrate_cvss(vul_info_file, node_file, edge_file, nodes):
	Gm = [1.0]
	vul_file = open(vul_info_file, "r")
	nodes = open(node_file, "r")
	edges = open(edge_file, "r")
	vul_list = []
	node_nums = []
	# Opens file made in list_vuls() and stores vulnerabilities in a array
	for line in vul_file:
		x = line.split()
		if x != []:
			vul_list.append(x)
	# Searches node file for nodes with vulExists() clauses, sets Gm[n] based on 
	# vulnerability info from vul_list
	for line in nodes:
		Gm = Gm + [1.0]
		if "vulExists" in line:
			for v in vul_list:
				if v[1] == 'h':
					v[1] = 0.2
				elif v[1] == 'm':
					v[1] = 0.6
				elif v[1] == 'l':
					v[1] = 0.9
				if v[0] in line:
					t = extract_node_num(line)
					Gm[t] = v[1]
					node_nums.append(t)
	for e in edges:
		t = e.split(',')
		if int(t[1]) in node_nums:
			Gm[int(t[0])] = Gm[int(t[1])]
	return Gm
# Reads the VERTICES.CSV file 
# and out puts nodes in form [[nodes, attack-step nodes, privilige nodes, root node], LEAF_nodes]
# nodes is an array of all non-leaf nodes
# attack-step nodes are the circular AND nodes on graph
# privilige nodes are diamond-shaped OR nodes on graph
# root node is rectangular node with clause "attackerLocated()."

def define_nodes(file): 
	nodes = []
	AND_nodes = []
	OR_nodes = []
	LEAF_nodes = []
	f = open(file, "r")
	for line in f:
		if "AND" in line:
			nodes.append(extract_node_num(line))
			AND_nodes.append(extract_node_num(line))
		elif "OR" in line:
			nodes.append(extract_node_num(line))
			OR_nodes.append(extract_node_num(line))
		elif "attackerLocated" in line:
			nodes.append(extract_node_num(line))
			ROOT_node = extract_node_num(line)
		else:
			LEAF_nodes.append(extract_node_num(line))
	return [[nodes, AND_nodes, OR_nodes, ROOT_node], LEAF_nodes]	 	                        

# Helper function to pull node numbers from a line in the file
def extract_node_num(string):
	node_num = []
	for i in string:
		if RepresentsInt(i):
			node_num.append(i)
		else:
			break
	if node_num == []:
		return ValueError
	else:
		return int("".join(node_num))		

# Implements Algorithm 1 from the paper
def cumulative_metric(nodes, edges):
	n = nodes[3]
	node_boo = [1] * (max(nodes[0]) + 1 )
	global delta_n_table
	global chi_n_table
	global prob_table
	global cond_prob_table
	chi_n_table = [None] * (max(nodes[0]) + 1)
	delta_n_table = [None] * (max(nodes[0]) + 1)
	prob_table = [None] * (max(nodes[0]) + 1)
	cond_prob_table = [None] * (max(nodes[0]) + 1)
	prob_table[nodes[3]] = 1.0 #Set root node probability to 1.0
	BRANCH_nodes = find_BRANCH_nodes(edges)
	U = nodes[0]
	U.remove(n)
	P = []
	while U != []:
		for node in U:
			if set(find_P(node, edges)) & set(U) == set([]):
				n = node
				break
		if n in nodes[2]:
			P = find_P(n, edges)
			prob_table[n] = 1 - (1 - evalProb(P, negate_boo(node_boo, P), nodes, edges))
			chi_n(n, nodes, BRANCH_nodes, P, edges)
			delta_n(n, nodes, BRANCH_nodes, P, edges)
			if n in BRANCH_nodes:
				psi_n = 1
		elif n in nodes[1]:
			P = find_P(n, edges)
			prob_table[n] = Gm[n] * evalProb(P, negate_boo(node_boo, P), nodes, edges)
			chi_n(n, nodes, BRANCH_nodes, P, edges)
			delta_n(n, nodes, BRANCH_nodes, P, edges)
		U.remove(n)
	return	

# Implements the function chi(n) from the paper 
def chi_n(n, nodes, BRANCH_nodes, P, edges):
	result = []
	global chi_n_table
	if n in BRANCH_nodes:
		result.append(n)
	if n == nodes[3]:
		if [n, result] not in chi_n_table:
						chi_n_table[n] = result
		return result
	elif n in nodes[2]:
		for node in P:
			 result = result + chi_n(node,  nodes, BRANCH_nodes, find_P(node, edges), edges)
		if [n, result] not in chi_n_table:
						chi_n_table[n] = result
		return result
	elif n in nodes[1]:
		for node in P:
			half = list(set(P) & set(BRANCH_nodes))
			result = result + chi_n(node,  nodes, BRANCH_nodes, find_P(node, edges), edges)
			result = list(set(half)| set(result))
		if [n, result] not in chi_n_table:
			chi_n_table[n] = result
		return result

# Implements delta(n) from the paper.
def delta_n(n, nodes, BRANCH_nodes, P, edges):
	result = []
	counter = 1
	global delta_n_table
	if n in BRANCH_nodes:
		result.append(n)
	if n == nodes[3]:
		if [n, result] not in delta_n_table:
				delta_n_table[n] = result
		return result
	elif n in nodes[2]:
		if len(P) == 1:
			result = delta_n(P[0], nodes, BRANCH_nodes, find_P(P[0], edges), edges)
		else:
			while counter in range(len(P)):
				#print("Counter value: ", counter)
				result = list(set(delta_n(P[counter - 1], nodes, BRANCH_nodes, find_P(P[counter - 1], edges), edges)) & set(delta_n(P[counter], nodes, BRANCH_nodes, find_P(P[counter], edges), edges)))
				counter = counter + 1
		delta_n_table[n] = result
		return result
	elif n in nodes[1]:
		for node in P:
			half = list(set(P) & set(BRANCH_nodes))
			result = result + delta_n(node,  nodes, BRANCH_nodes, find_P(node, edges), edges) 
			result = list(set(half)| set(result))
		#print("Attack-Step at ", n)
		delta_n_table[n] = result
		return result

# Implements Algorithm 2 from Paper
def evalProb(N, node_boo, nodes, edges):
	#N is set of nodes already evaluated
	#U is set of nodes not evaluated yet
	global prob_table
	global chi_n_table
	Prob = 1.0
	Prob_Sum = 0
	D = find_D_set(N, chi_n_table)
	if D == []:
		for i in N:
			if prob_table[i] != None:
				Prob = Prob * prob_table[i]
		return Prob
	else:
		# Sum all possible values of D for cyclic graph
		Prob_Sum = Prob_Sum + evalCondProb(D, N, node_boo, nodes, edges) * evalProb(D, node_boo, nodes, edges)
		return Prob_Sum

# Implements Algorithm 3 from paper

def evalCondProb(D, N, node_boo, nodes, edges):
	#node_boo is an array containing boo values for nodes
	#Ex: Node 5's boo value will be at node_boo[5]
	K = []
	J = []
	cond_prob = 1.0
	global cond_prob_table
	global prob_table
	global chi_n_table
	global delta_n_table
	if len(N) > 1:
		for node in N:
			node_cond_prob = evalCondProb(D, [node], node_boo, nodes, edges)
			cond_prob_table[node] = node_cond_prob
			cond_prob = cond_prob * node_cond_prob
		return cond_prob		
	elif len(N) == 1 and node_boo[N[0]] == 0:
		cond_prob = 1 - evalCondProb(D, [N[0]], negate_boo(node_boo, N), nodes, edges)
		return cond_prob
	else:
		N = N[0]
		if D != []:
			if node_boo[D[0]] == 1:
				J.append(D[0])
			elif node_boo[D[0]] == 0:
				K.append(D[0])
		if N in J:
			return 1
		if N in K:
			return 0
		elif list(set(K) & set(delta_n_table[N])) != []:
			return 0
		if list(set(D) & set(chi_n_table[N])) == []:
			return prob_table[N]
		P = find_P(N, edges)
		if N in nodes[2]:
			return 1 - evalCondProb(find_D_set(P, chi_n_table), P, negate_boo(node_boo, P), nodes, edges)
		elif N in nodes[1]:
			return Gm[N] * evalCondProb(find_D_set(P, chi_n_table), P, node_boo, nodes, edges)

# Find set of immediate predcessors for node n

def find_P(n, edges):
	P = []
	for e in edges:
		if e[0] == n:
			P.append(e[1])
	return P	

# Find immediate child nodes of node n. Proved redundant and wasn't needed for algorithm.
#def find_child_nodes(n, edges):
	#result = []
	#for e in edges:
		#if e[1] == n:
			#result.append(e[0])
	#return result

# Finds d-seperating set D for node set N

def find_D_set(N, chi_n_table):	
	if len(N) < 2:
		return []
	Pairs = list(itertools.combinations(N, 2))
	D = set()
	for p in Pairs:
		#print(p[0])
		#print(p[1])
		D = D | (set(chi_n_table[p[0]]) & set(chi_n_table[p[1]]))
	return list(D)

# Flip the values in the boo_lean list for nodes in set N
def negate_boo(boo_list, N):
	for b in range(len(boo_list)):
		if b in N:
			if boo_list[b] == 1:
				boo_list[b] = 0
			else:
				boo_list[b] = 1
	return boo_list

# Find all branch nodes from the attack graph

def find_BRANCH_nodes(edges):
	BRANCH_nodes = []
	root_nodes = []
	for e in edges:
		if e[1] in root_nodes:
			BRANCH_nodes.append(e[1])
		else:
			root_nodes.append(e[1])
	return BRANCH_nodes	

# Helper function for extract_node_num()

def RepresentsInt(s):
	try: 
		int(s)
		return True
	except ValueError:
		return False

# Open the ARCS.CSV file and list the edges

def define_edges(file, nodes):
	f = open(file, "r")
	edges = []
	for line in f:
		line = line.split(',')
		if int(line[0]) in nodes and int(line[1]) in nodes:
			edges.append([int(line[0]), int(line[1])])	
	return edges

if __name__ == '__main__':
	main()
