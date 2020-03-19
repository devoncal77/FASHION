from sympy import sympify, Symbol, symbols, numbered_symbols, simplify, latex, Matrix
from sys import argv
from fractions import Fraction
from itertools import product,permutations, combinations
from functools import reduce
from operator import mul
from random import random,randrange

def intersection(values):
    return sum(((-1) ** (i)) * sum(reduce(mul, terms) for terms in combinations(values, i+1)) for i in range(len(values)))


class bayesian_network:
    def __init__(self):
        self.nodes = {}
        self.unions = set()
        self.edges = {}
        self.reverse_edges = {}
    # Gets the probability an attacker reaches a specific node
    def get_probability(self, node):
        if node not in self:
            return float('inf')
        if len(self.reverse_edges[node]) == 0:
            return self.nodes[node]
        if node in self.unions:
            return self.nodes[node] * reduce(mul, map(lambda i: self.get_probability(i), self.reverse_edges[node]))
        return self.nodes[node] * intersection(list(map(lambda i: self.get_probability(i), self.reverse_edges[node])))
        
    
    def add_node(self, id, weight=Fraction(1), union=False):
        self.nodes[id] = weight
        self.edges[id] = set()  
        self.reverse_edges[id] = set()
        if union:
            self.unions.add(id)
    
    def toggle_union(self, id):
        if id not in nodes:
            return
        if id in self.unions:
            self.unions.remove(id)
        else:
            self.unions.add(id)
    
    def add_edge(self, i, j):
        if i not in self or j not in self:
            return
        if i not in self.edges:
            self.edges[i] = set()
        if j not in self.reverse_edges:
            self.reverse_edges[j] = set()
        self.edges[i].add(j)
        self.reverse_edges[j].add(i)
        
    def remove_edge(self, i, j):
        if i not in self or j not in self:
            return
        if j not in self.edges[i] or i not in self.reverse_edges[j]:
            return
        self.edges[i].remove(j)
        self.reverse_edges[j].remove(i)
    
    def __contains__(self, node):
        return node in self.nodes
    
    def get_edges_from(self, node):
        return self.edges[node]
        
    def get_edges_to(self, node):
        return self.reverse_edges[node]
    
    def get_weight(self, node):
        return self.nodes[node]



def laplacian(G):
    matrix = [[0]*len(G.nodes) for _ in range(len(G.nodes))]
    enumerated_nodes = dict(enumerate(G.nodes.keys(),0))
    for i in range(len(G.nodes)):
        for j in range(len(G.nodes)):
            if i == j:
                matrix[i][j] = G.nodes[enumerated_nodes[i]] * len(G.edges[enumerated_nodes[i]])
            elif enumerated_nodes[j] in G.edges[enumerated_nodes[i]]:
                matrix[i][j] = -G.nodes[enumerated_nodes[i]]
            else:
                matrix[i][j] = 0
    return Matrix(matrix)

def spaning_trees(G):
    laplacianG = laplacian(G)
    # print(latex(laplacianG))
    # print("trees:")
    eigens = list(laplacianG.eigenvals().keys())
    return simplify(reduce(mul, (i if i != 0 else 1 for i in eigens))/len(eigens))


def main(args):
    symbol_generator = numbered_symbols('n')
    
    G = bayesian_network()
    G.add_node('internet')
    for i in range(12):
        G.add_node(f'n{i}', next(symbol_generator))
    for i in range(5):
        G.add_node(f'd{i}')
    subgraph_connections = {
    'd0':['n3','n4'],
    'd1':['n5','n6'],
    'd2':['n7'],
    'd3':['n8'],
    'd4':['n9'],
    'd5':['n10']
    }
    for i in subgraph_connections.keys():
        for j in subgraph_connections[i]:
            G.add_node(f'{i}->{j}',Fraction(randrange(1,2),randrange(1,2)))
    G.add_node('goal')
    
    G.add_edge('internet', 'n0')
    G.add_edge('internet', 'n1')
    G.add_edge('internet', 'n2')
    G.add_edge('n0', 'd0')
    G.add_edge('n1', 'd1')
    G.add_edge('n2', 'd2')
    
    for i in subgraph_connections.keys():
        for j in subgraph_connections[i]:
            id = f'{i}->{j}'
            G.add_edge(i,id)
            G.add_edge(id,j)
    G.add_edge('n3','d3')
    G.add_edge('n4','d4')
    G.add_edge('n5','d4')
    G.add_edge('n6','d5')
    G.add_edge('n7','d5')
    G.add_edge('n8','goal')
    G.add_edge('n9','goal')
    G.add_edge('n10','goal')
    
    
    print(latex(laplacian(G)))
    print()
    # print(G.nodes)
    print(latex(simplify(G.get_probability('goal'))))
    print(spaning_trees(G))
    
    G2 = bayesian_network()
    for i in range(6):
        G2.add_node(i)
    for i,j in ((4,6),(4,5),(4,3),(2,3),(2,5),(2,1),(5,1)):
        G2.add_edge(i-1,j-1)
        G2.add_edge(j-1,i-1)
    # G2.add_edge(6,4)
    # G2.add_edge(4,5)
    # G2.add_edge(4,3)
    # G2.add_edge(5,2)
    # G2.add_edge(5,1)
    # G2.add_edge(3,2)
    # G2.add_edge(2,1)
    print()
    
    print()
    print(G2.edges)
if __name__ == "__main__":
    main(argv)