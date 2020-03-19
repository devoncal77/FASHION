from fractions import Fraction
from random import random
from numbers import Real


def intersection(p):
    out: Real = 0
    for i in p:
        out = i + out - i * out
    return out


def intersection_representation(p):
    p = list(p)
    out = p[0]
    for i in p[1:]:
        out = simplify(('+', i, ('*', out, ('-', '1', i))), deep=False)
    return out


class BayesianNetwork:
    def __init__(self):
        self.nodes = {}
        self.edges = {}
        self.reverse_edges = {}

    def get_probability(self, start, stop):
        if start not in self or stop not in self:
            return float('inf')
        ordering = self.topological_sort()
        likleyhood = {node: 0 for node in ordering}
        likleyhood[start] = 1
        for node in ordering[1:]:
            likleyhood[node] = intersection(likleyhood[neighbor] for neighbor in self.get_edges_to(node)) * self.nodes[node]
        return likleyhood[stop]

    def get_representation(self, start, stop):
        if start not in self or stop not in self:
            return str(float('inf'))
        ordering = self.topological_sort()
        likleyhood = {node: str(0) for node in ordering}
        likleyhood[start] = str(1)
        for node in ordering[1:]:
            # likleyhood[node] = f'{self.nodes[node]}*{intersection_representation(likleyhood[neighbor] for neighbor in self.get_edges_to(node))}'
            # likleyhood[node] = f'''(* {self.nodes[node]} {intersection_representation(likleyhood[neighbor] for neighbor in self.get_edges_to(node))})'''
            likleyhood[node] = simplify(('*', f'{self.nodes[node]}', intersection_representation(likleyhood[neighbor] for neighbor in self.get_edges_to(node))), deep=False)
            # before = likleyhood[node]
            # after = simplify(likleyhood[node])
        return likleyhood[stop]

    def get_flat_repr(self, start, stop):
        ordering = self.topological_sort()
        likleyhood = {node: str(0) for node in ordering}
        likleyhood[start] = str(1)
        for node in ordering[1:]:
            pass
        return likleyhood[stop]

    def topological_sort(self):
        def topological_sort_util(v, visited, stack):
            visited.add(v)
            for node in self.get_edges_from(v):
                if node not in visited:
                    topological_sort_util(node, visited, stack)
            stack.insert(0, v)
        visited = set()
        stack = []
        for node in self.nodes.keys():
            if node not in visited:
                topological_sort_util(node, visited, stack)
        return stack

    def add_node(self, id, weight):
        self.nodes[id] = weight
        self.edges[id] = set()
        self.reverse_edges[id] = set()

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


def simplify(lisp, deep=True):
    # pprint(lisp)
    # print()
    # return lisp
    if type(lisp) is str:
        return lisp
    if lisp[0] == '*':
        if (lisp[1] == '0' or lisp[2] == '0'):
            return '0'
        if lisp[1] == '1' and lisp[2] == '1':
            return '1'
        if lisp[1] == '1':
            if deep:
                return simplify(lisp[2])
            else:
                return lisp[2]
        elif lisp[2] == '1':
            if deep:
                return simplify(lisp[1])
            else:
                return lisp[1]

    if lisp[1] == '1' and lisp[2] == '1':
        if lisp[0] == '+':
            return '2'
        else:  # Subtraction
            return '0'
    if lisp[1] == '0' and lisp[2] == '0':
        return '0'
    if (lisp[1] == '0' and lisp[2] == '1') or (lisp[1] == '1' and lisp[2] == '0'):
        if lisp[0] == '+':
            return '1'
        elif lisp[0] == '0':
            return '-1'
        else:
            return '1'
    if deep:
        out = (lisp[0], simplify(lisp[1]), simplify(lisp[2]))
    else:
        out = lisp
    if out[0] == '+' and type(out[1]) != tuple and type(out[2]) == tuple and out[2][0] == '-' and out[2][1] == '1' and out[2][2] == out[1]:
        return '1'
    # if out[0] == '*' and type(out[2]) == tuple and out[2][0] == '*':
    #     out = (out[0], out[1]) + out[2][1:]
    # if out[1] == '*' and type(out[1]) == tuple and out[1][0] == '*':
    #     out = (out[0], out[1][1], out[1][2])
    return out


def test_remove_nodes(G):
    nodes = set(G.nodes.keys()).copy()
    while(True):
        start = G.get_probability("source", "sink")
        best = start
        removal = None
        for node in nodes:
            edges = G.get_edges_from(node).copy()
            for edge in edges:
                G.remove_edge(node, edge)
            current = G.get_probability("source", "sink")
            if current < best and current != 0:
                best = current
                removal = node
            for edge in edges:
                G.add_edge(node, edge)
        if removal is None:
            break
        # nodes.remove(removal)
        for edge in G.get_edges_from(removal).copy():
            G.remove_edge(removal, edge)
        for edge in G.get_edges_to(removal).copy():
            G.remove_edge(edge, removal)


def test_remove_edges(G):
    nodes = set(G.nodes.keys()).copy()
    depth = 0
    while(True):
        start = G.get_probability("source", "sink")
        best = start
        removal = None
        for node in nodes:
            edges = G.get_edges_from(node).copy()
            for edge in edges:
                G.remove_edge(node, edge)
                current = G.get_probability("source", "sink")
                # print(current)
                if current < best and current != 0:
                    best = current
                    removal = (node, edge,)
                G.add_edge(node, edge)
        if removal is None:
            break
        depth += 1
        print(f'{depth:>6}: removing {removal[0]:>6}->{removal[1]:<6s} reduction of {(1-(best/start))*100}%')
        G.remove_edge(*removal)


def k_G(size, restrict=False, generator=lambda: random() / 2, source='source', sink='sink'):
    G = BayesianNetwork()
    G.add_node(source, 1)
    G.add_node(sink, 1)
    nodes = [f'n{i}' for i in range(size)]
    for node in nodes:
        G.add_node(node, generator())
    for i in nodes:
        for j in nodes:
            if i is j or j in G.get_edges_to(i):
                continue
            if restrict and len(G.get_edges_from(i)) > 6:
                continue
            G.add_edge(i, j)
    for node in nodes:
        G.add_edge(node, 'sink')
        G.add_edge('source', node)
    return G


def toggle_G(size, restrict=False, generator=lambda: random() / 2, node_generator=lambda: 1, source='source', sink='sink'):
    G = BayesianNetwork()
    G.add_node(source, 1)
    G.add_node(sink, 1)
    nodes = [f'n{i}' for i in range(size)]
    for node in nodes:
        G.add_node(node, node_generator())
    paths = set()

    def add_intermediary(begin, end):
        temp_node = f'({begin}->{end})'
        G.add_node(temp_node, generator())
        G.add_edge(begin, temp_node)
        G.add_edge(temp_node, end)
    for i in nodes:
        for j in nodes:
            if i is j or (j, i) in paths:
                continue
            # if restrict and len(G.get_edges_from(i)) > 6:
            #     continue
            add_intermediary(i, j)
            paths.add((i, j,))
    for node in nodes:
        add_intermediary(node, 'sink')
        add_intermediary('source', node)
    return G


def test(i: int):
    G = k_G(i, True)
    test_remove_edges(G)


def main():
    from booleanpolynomial import numbered_polynomials
    edge_gen = numbered_polynomials('e')
    G = toggle_G(5, generator=lambda: next(edge_gen), node_generator=lambda: random())
    print(G.get_probability('source', 'sink'))


if __name__ == "__main__":
    main()
