from collections import defaultdict, namedtuple
from functools import reduce
from operator import mul
from dataStructures.booleanGraph import HostNode, ExploitNode, BooleanGraph
from tarjan import tarjan_iter
from fractions import Fraction

def trimAttackGraph(AG, cuts):
    pass

def andCalc(*terms):
    terms = list(terms)
    if len(terms) == 0:
        return 0
    return reduce(mul, terms)

def orCalc(*terms):
    out = 0
    for i in terms:
        out = i + out - i * out
    return out

def andRepr(*terms):
    terms = list(terms)
    if len(terms) == 0:
        return 0
    return ("*",) + tuple(terms) 

def orRepr(*terms):
    p = list(terms)
    if len(p)  == 0:
        return 0
    out = p[0]
    for i in p[1:]:
        out = ('+', i, ('*', out, ('-', '1', i)))
    return out

def wrapSolution(solution, model):
    active = model.m.getAttr('x',model.active) # Get conn
    active = set(filter(lambda k : active[k] > 0.1,active.keys())) # filter to connected only
    pred = defaultdict(set)
    succ = defaultdict(set)
    nodes = set()
    for i, j in active:
        succ[i].add(j)
        pred[j].add(i)
        nodes.add(i)
        nodes.add(j)
    FakeAG = namedtuple("FakeAG", ["succ", "pred", "gateways", "nodes"])
    return FakeAG(succ=succ, pred=pred, nodes=nodes, gateways=model.AG.gateways), model.compCost

def cyclicalRisk(AG, compCost):
    sc = list(tarjan_iter(AG.succ))
    components = sc[::-1] # Tarjan outputs reverse topological order
    P = {g:1 for g in AG.gateways}
    def helper(v, ignored, P, fakeP = None):
        isReal = fakeP == None
        if isReal:
            fakeP = dict(P)
        for node in AG.pred[v]:
            cond1 = (node, v) in ignored
            cond2 =  node not in fakeP.keys()
            if cond1:
                continue
            if cond2:
                subIgnore = set((node, i) for i in AG.succ[node]) | ignored
                helper(node, subIgnore, P, fakeP)
        if isinstance(v, ExploitNode):
            fakeP[v] = andCalc(andCalc(*[fakeP[i] if (i,v) not in ignored else 0 for i in AG.pred[v]]), Fraction(str(v.probability)))
        else: # HostNode
            fakeP[v] = orCalc(*[fakeP[i] for i in AG.pred[v] if (i,v) not in ignored]) # Prob is always 1
        if isReal:
            return fakeP[v]
    for component in components:
        if len(component) == 1:
            node = next(iter(component))
            if node in AG.gateways:
                continue
            elif isinstance(node, ExploitNode):
                P[node] = andCalc(andCalc(*[P[i] for i in AG.pred[node]]), Fraction(str(node.probability)))
            else: # HostNode
                P[node] = orCalc(*[P[i] for i in AG.pred[node]]) # Prob is always 1
        else:
            for node in component:
                if node in P.keys():
                    continue
                P[node] = helper(node, set((node, i) for i in AG.succ[node]),dict(P))
    hosts = {i for i in AG.nodes if isinstance(i, HostNode) and i.permission == 0}
    netHosts = defaultdict(list)
    for node in hosts:
        netHosts[node.host].append(P[node])
    return (len([i for i in sc if len(i) > 1]),sum(P[i] * compCost[i.host, i.permission] for i in AG.nodes - hosts if isinstance(i, HostNode)) + sum(compCost[host, 0]*orCalc(*bucket) for host, bucket in netHosts.items()))
        
        




