from collections import defaultdict
from itertools import product, chain, combinations
from graphviz import Digraph
from gurobipy import Model, GRB, quicksum
import logging
from argparse import ArgumentParser, ArgumentError
from time import time


class DAG:
    def __init__(self):
        self._vertices = set()
        self._edges = defaultdict(set)
        self._reverseEdges = defaultdict(set)
        self._exploitEdges = set()

    def add_edge(self, i, j, exploit=False):
        self.add_vertex(i)
        self.add_vertex(j)
        self._edges[i].add(j)
        self._reverseEdges[j].add(i)
        if exploit:
            self._exploitEdges.add((i, j))

    def add_vertex(self, label):
        self._vertices.add(label)

    def __getitem__(self, key):
        return self._edges[key]

    def __contains__(self, key):
        return key in self._vertices

    def render(self, initial=None):
        visited = set()
        if initial is not None:
            stack = [((initial, 0),)]
            while len(stack) != 0:
                current = stack.pop()
                if current in visited:
                    continue
                visited.add(current)
                stack.extend(self._edges[current])
        else:
            for i, j in self._reverseEdges:
                if len(j) == 0:
                    visited.add(i)

        dot = Digraph()
        # print(dot.engine)

        def getLabel(node):
            return "\n".join(f'{i[0]} : {i[1]}' for i in node)
        for node in self._vertices:
            if ((initial, 0),) == node:
                dot.node(str(node), label=getLabel(node), style='filled', color='lightgrey')
            elif node in visited:
                dot.node(str(node), label=getLabel(node), style="filled", color='lime')
            else:
                dot.node(str(node), label=getLabel(node))
        for start, stops in self._edges.items():
            for stop in stops:
                dot.edge(str(start), str(stop), None, {"color": "red"} if (start, stop) in self._exploitEdges else None)
        # print(dot.engine)
        # dot.engine = "sfdp"
        dot.render('test-output/DAG.gv', view=True, cleanup=True, format="svg")


class AttackGraph:
    def __init__(self, graph, costs):
        self.G = graph
        self.C = costs

    def runModel(self, timeout=None, initial=None):
        if timeout is not None and timeout < 0:
            logging.error(f"Timeout {timeout} must be positive.")
            return
        if timeout is not None:
            logging.info(f"Running model with timeout of {timeout}.")
        else:
            logging.warning(f"Running model with no timeout!")
        start_time = time()
        edges = []
        for start, k in self.G._edges.items():
            for stop in k:
                edges.append((start, stop))
        model = Model("Attack Graph")
        reachable = model.addVars([vertex for vertex in self.G._vertices], vtype=GRB.BINARY, name="reachable")
        active = model.addVars(edges, vtype=GRB.BINARY, name="active")
        aux = model.addVars(edges, vtype=GRB.BINARY, name="aux")
        model.update()
        for vertex in self.G._vertices:
            if len(self.G._reverseEdges[vertex]) == 0:
                continue
            model.addGenConstrOr(reachable[vertex], [aux[start, vertex] for start in self.G._reverseEdges[vertex]])
        for edge in edges:
            model.addGenConstrAnd(aux[edge], [reachable[edge[0]], active[edge]])
        for start, stop in self.G._exploitEdges:
            model.addConstr(active[start, stop] == 1)
        if initial is None:
            for vertex in self.G._vertices:
                if len(self.G._reverseEdges[vertex]) == 0:
                    model.addConstr(reachable[vertex] == 1)
        else:
            for vertex in self.G._vertices:
                if len(self.G._reverseEdges[vertex]) == 0 and vertex != ((initial, 0),):
                    model.addConstr(reachable[vertex] == 0)
            model.addConstr(reachable[((initial, 0),)] == 1)
        model.update()
        model.setObjective(quicksum(reachable[vertex] * self.C[vertex] for vertex in self.G._vertices), GRB.MINIMIZE)
        model.update()
        end_time = time()
        logging.info(f"Built model in {end_time-start_time}")
        model.optimize()


def powerset(iterable):
    "powerset([1,2,3]) --> () (1,) (2,) (3,) (1,2) (1,3) (2,3) (1,2,3)"
    s = list(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(len(s) + 1))


def validate_permisions(i, j):
    # changes = len(j) - len(i)
    for label in i.keys():
        if label not in j:
            return True
        if j[label] != i[label]:
            return True
    if len(j) - len(i) != 1:
        return True
    if j[list(j.keys() - i.keys())[0]] != 0:
        return True
    # if changes > 1:
    #     return True
    return False


def pair(arg):
    if ':' not in arg:
        raise ArgumentError
    i, _, j = arg.partition(":")
    try:
        j = int(j)
    except ValueError:
        raise ArgumentError
    if j < 0:
        raise ArgumentError
    return i, int(j)


def exploit(arg):
    if "->" not in arg:
        raise ArgumentError
    i, _, j = arg.partition("->")
    return tuple(pair(k) for k in i.split(",")), pair(j)


def exploitable(vertex, precedents):
    for i, j in precedents.items():
        if i not in vertex or vertex[i] < j:
            return False
    return True


def main():
    # logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
    parser = ArgumentParser(description="Generates a linear model for attack graphs")
    parser.add_argument("--hosts", nargs='+', help='<Required> [Host]:[Max Permission] pairs', required=True, type=pair)
    parser.add_argument("--exploits", nargs='+', help="[Host]:[Max Per],...->[Host]:[Max Per]", type=exploit, default=[])
    parser.add_argument("-r", "--render", help="render the graph", action="store_true")
    parser.add_argument("-t", "--timeout", help="Max time to run the model", type=int)
    parser.add_argument("-s", "--start", help="The host at which to start")
    args = parser.parse_args()
    lables = []
    for i, j in args.hosts:
        temp = []
        for level in range(j):
            temp.append((i, level))
        lables.append(temp)
    G = DAG()
    for entries in powerset(lables):
        for label in product(*entries):
            if len(label) == 0:
                continue
            G.add_vertex(label)
    for i, j in product(G._vertices, G._vertices):
        if i == j:
            continue
        from_dict = dict(i)
        to_dict = dict(j)
        if len(from_dict) > len(to_dict):
            continue
        if validate_permisions(from_dict, to_dict):
            continue
        G.add_edge(i, j)
    for i, j in args.exploits:
        precedents = dict(i)
        for vertex in G._vertices:
            vertex_dict = dict(vertex)
            if exploitable(vertex_dict, precedents) and vertex_dict[j[0]] < j[1]:
                vertex_dict[j[0]] = j[1]
                G.add_edge(vertex, tuple(zip(vertex_dict.keys(), vertex_dict.values())), exploit=True)
    if args.render:
        G.render(initial=args.start)
    AttackGraph(G, defaultdict(lambda: 10)).runModel(timeout=args.timeout, initial=args.start)


if __name__ == "__main__":
    main()
