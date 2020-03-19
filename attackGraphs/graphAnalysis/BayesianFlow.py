from itertools import product,permutations, combinations
from functools import reduce
from operator import mul
from fractions import Fraction

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
        
    
    def add_node(self, id, weight, union=False):
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

class weighted_graph:
    def __init__(self):
        self._G = {}

    def add_node(self, node):
        if node not in self:
            self._G[node] = {}

    def __contains__(self, item):
        return item in self._G

    # If an edge (i,j) already exists, than this will override it
    # This is not a multigraph
    def add_edge(self, i, j, w):
        self.add_node(i) # Adding a node never overides previous values
        self.add_node(j)
        self._G[i][j] = w

    def __getitem__(self,i):
        if i in self:
            return self._G[i]
        return {}


    def __getitem__(self, i, j):
        if i in self and j in self:
            return self._G[i][j]
        return float('inf')
        

def test_graph(G, sink="root", source=""):
    root_prob = G.get_probability(sink)
    max_id_len = max(len(id) for id in G.nodes.keys())
    for begin, neighbors in G.edges.items():
        old_neighbors = neighbors.copy()
        for end in old_neighbors:
            G.remove_edge(begin, end)
        print(f'Removing {begin:{max_id_len}s} with {len(G.reverse_edges[begin])} in and {len(old_neighbors)} out | {float(root_prob):.6f} -> {float(G.get_probability(sink)):.6f} | {float((-G.get_probability(sink)+root_prob)/float(G.get_probability(sink)))*100:3.0f}% decrease')
        for end in old_neighbors:
            G.add_edge(begin, end)

def main():
    # G = {f'e{e}' : {} for e in range(1,9)}
    # G['e2']['e6'] = .3
    # G['e1']['e4'] = .2
    # G['e3']['c1']
    # G = weighted_graph()
    # for i in range(1,9):
    #     G.add_node(f'e{i}')
    # G.add_edge('e2', 'e6', .3)
    # G.add_edge('e1', 'e4', .2)
    # G.add_edge('e3', 'c1', .4)
    # G.add_edge('e6', 'c2', .7)
    # G.add_edge('e4', 'c1', .5)
    # G.add_edge('c2', 'e8', )
    G = bayesian_network()
    G.add_node('e1', Fraction(2,10))
    G.add_node('e2', Fraction(3,10))
    G.add_node('e3', Fraction(4,10))
    G.add_node('e4', Fraction(5,10))
    G.add_node('e5', Fraction(6,10))
    G.add_node('e6', Fraction(7,10))
    G.add_node('e7', Fraction(8,10))
    G.add_node('root', Fraction(1,1))
    G.add_node('c1',Fraction(1),union=True)
    
    G.add_edge('e1', 'e4')
    G.add_edge('e2', 'e6')
    G.add_edge('e3', 'e5')
    G.add_edge('e4', 'e5')
    G.add_edge('e5', 'e7')
    G.add_edge('e6', 'c1')
    G.add_edge('e7', 'c1')
    G.add_edge('c1', 'root')
    
    print(G.nodes)
    print(intersection([.5,.1]))
    print(intersection([.1,.5]))
    for node in G.nodes.keys():
        print(f'{node} : {float(G.get_probability(node))}')
    test_graph(G)
    print('================== G2 ==================')
    G2 = bayesian_network()
    for i in range(1,7):
        G2.add_node(f'e{i}',Fraction(i,10))
    G2.add_node('root', Fraction(1))
    G2.add_edge('e6', 'e4')
    G2.add_edge('e6', 'e3')
    G2.add_edge('e5', 'e4')
    G2.add_edge('e5', 'e3')
    G2.add_edge('e4', 'e2')
    G2.add_edge('e4', 'e1')
    G2.add_edge('e3', 'e2')
    G2.add_edge('e3', 'e1')
    G2.add_edge('e2', 'root')
    G2.add_edge('e1', 'root')
    for node in G2.nodes.keys():
        print(f'{node} : {float(G2.get_probability(node))}')
    test_graph(G2)
    G3 = bayesian_network()
    G3.add_node('1',.5)
    G3.add_node('2',.3)
    G3.add_node('3',.6)
    G3.add_node('4',.2)
    G3.add_node('5',.8)
    G3.add_node('6',.4)
    G3.add_node('7',.7)
    G3.add_node('8',.4)
    G3.add_node('9',.9)
    G3.add_node('source', 1)
    G3.add_node('sink',1)
    
    G3.add_edge('source','1')
    G3.add_edge('source','2')
    G3.add_edge('source','3')
    G3.add_edge('1','4')
    G3.add_edge('1','5')
    G3.add_edge('2','9')
    G3.add_edge('3','6')
    G3.add_edge('4','7')
    G3.add_edge('5','6')
    G3.add_edge('6','9')
    G3.add_edge('6','8')
    G3.add_edge('7','sink')
    G3.add_edge('8','sink')
    G3.add_edge('9','8')
    
    for node in G3.nodes.keys():
        print(f'{node} : {float(G3.get_probability(node))}')
    
    test_graph(G3, sink="sink")
    
if __name__ == '__main__':
    main()