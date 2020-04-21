from itertools import chain, permutations, product, combinations
from collections import defaultdict, namedtuple
from sets import Set
from time import time

def powerset(iterable):
    "powerset([1,2,3]) --> () (1,) (2,) (3,) (1,2) (1,3) (2,3) (1,2,3)"
    s = list(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(len(s) + 1))

def validate_permisions(i, j):
    for label in i.keys():
        if label not in j:
            return True
        if j[label] != i[label]:
            return True
    if len(j) - len(i) != 1:
        return True
    if j[list(set(j.keys()) - set(i.keys()))[0]] != 0:
        return True
    return False

def exploitable(vertex, precedents):
    for i, j in precedents.items():
        if i not in vertex or vertex[i] < j:
            return False
    return True

class Exploit:
    def __init__(self, prereqs, outcome, networkPrereqs):
        self.prereqs = prereqs
        self.outcome = outcome
        self.networkPrereqs = networkPrereqs

class AttackGraph:
    def __init__(self, V, succ, pred, exploitEdges, hostPerms, exploits, buildTime, nbPerms):
        self.V = V
        self.succ = succ
        self.pred = pred
        self.exploitEdges = exploitEdges
        self.hostPerms = hostPerms
        self._exploits = exploits
        self.buildTime = buildTime
        self.nbPerms = nbPerms

    def exploitEdges(self):
        return iter(self.exploitEdges)

    def networkEdges(self):
        for edge in self.edges():
            if edge not in self.exploitEdges:
                yield edge

    def edges(self):
        for i,j in self.succ.items():
            for k in j:
                yield i,k

    def prereqVerticies(self, prereq):
        return set.intersection(*(self.hostPerms[hostPerm] for hostPerm in prereq.items()))

    def nbNodes(self):
        return len(self.V)

    def nbEdges(self):
        return sum(len(i) for i in self.succ.values())

    def nbExploits(self):
        return len(self._exploits)
    
    def rangeSizeExploits(self):
        min = 100000000
        max = 0
        for e in self._exploits:
            min = len(e.prereqs) if len(e.prereqs) < min else min
            max = len(e.prereqs) if len(e.prereqs) > max else max
        return (min,max)

    def nbPermissions(self):
        return self.nbPerms

    def avgDegIn(self):
        degIn = [len(i) for i in self.pred.values()]
        return sum(degIn) / len(degIn)

    def avgDegOut(self):
        degOut = [len(i) for i in self.pred.values()]
        return sum(degOut) / len(degOut)

    def avgDeg(self):
        deg = [len(self.pred.get(i,set())) + len(self.succ.get(i,set())) for i in self.V]
        return sum(deg) / len(deg)

    @staticmethod
    def fromJson(dict):
        buildStart = time()
        nbPerms = 0
        V = set()
        succ = defaultdict(set)
        pred = defaultdict(set)
        nodesWith = {}
        trafficTypes = dict["traffics"]
        # make all possible nodes and network edges
        # stack = [AttackNode({int(g) : 0}, {int(g) : frozenset([t])}) for g in dict["gateways"] for t in trafficTypes]
        stack = [AttackNode({int(g) : 0}, {}) for g in dict["gateways"]]
        V.update(stack)
        while len(stack) > 0:
            current = stack.pop(0)
            for tType in trafficTypes:
                for h, lvls in dict["permissionLevels"].items():
                    h = int(h)
                    nbPerms = max(nbPerms,lvls)
                    if tType in current.hostTraffic.get(h, set()) or h in dict["gateways"]:
                        continue
                    for l in range(lvls):
                        temp = current.addHost(h, l, frozenset([tType]))
                        if l == 0:
                            succ[current].add(temp)
                            pred[temp].add(current)
                        if temp in V:
                            continue
                        V.add(temp)
                        stack.append(temp)
        # make exploit edges
        hostPerms = defaultdict(set)
        for vertex in V:
            for hostPerm in vertex:
                for i in range(hostPerm[1],dict["permissionLevels"][str(hostPerm[0])]):
                    hostPerms[hostPerm[0], i].add(vertex)
        jsonPrereq = lambda prereq : set() if not prereq else set.intersection(*(hostPerms[hostPerm] for hostPerm in prereq))
        exploitEdges = set()
        exploits = set()
        for e in dict["exploits"]:
            prereq = AttackNode({i:j for i,j in e["prereq"]["permissions"]}, {i:frozenset(j) for i,j in e["prereq"]["network"]})
            for host in prereq.hostTraffic.keys()[:]:
                prereq = prereq.addHost(host)
            benefit = AttackNode({e["outcome"][0] : e["outcome"][1]}, {})
            exploits.add(Exploit({i:j for i,j in e["prereq"]["permissions"]}, (e["outcome"][0], e["outcome"][1]), {i:j for i,j in e["prereq"]["network"]}))
            for p in jsonPrereq(prereq):
                temp = p.hostPermUnion(benefit)
                if len(temp) > len(p):
                    continue
                exploitEdges.add((p, temp))
                succ[p].add(temp)
                pred[temp].add(p)
        # Filter unreachable nodes
        stack = [AttackNode({int(g) : 0}, {}) for g in dict["gateways"]]
        visited = set(stack)
        while stack:
            top = stack.pop()
            stack.extend(i for i in succ[top] if i not in visited)
            visited.update(succ[top])
        detached = V - visited
        for node in detached:
            try:
                del succ[node]
                del pred[node]
            except KeyError:
                pass
        for l in succ.values() + pred.values():
            l-=detached
        for nodes in hostPerms.values():
            nodes -= detached
        succ = {k:v for k, v in succ.items() if v}
        pred = {k:v for k, v in pred.items() if v}
        V = visited
        exploitEdges = set((k,v) for k,l in succ.items() for v in l if (k,v) in exploitEdges)
        buildEnd = time()
        buildTime = buildEnd - buildStart
        return AttackGraph(V, succ, pred, exploitEdges, hostPerms, exploits, buildTime, nbPerms)

class AttackNode:
    currId = 0
    def __init__(self, hostPerms, hostTraffic):
        self.hostPerms = hostPerms
        self.hostTraffic = hostTraffic
        self.hosts = set(hostPerms.keys())
        self._hash = hash(frozenset(hostPerms.items()) | frozenset(hostTraffic.items()))
        self.id = AttackNode.currId
        AttackNode.currId += 1

    def addHost(self, host, perm=0, traffic=frozenset()):
        hostPerms = self.hostPerms.copy()
        hostPerms[host] = perm
        hostTraffic = self.hostTraffic.copy()
        if host in hostTraffic:
            hostTraffic[host] |= frozenset(traffic)
        else:
            hostTraffic[host] = frozenset(traffic)
        return AttackNode(hostPerms, hostTraffic)
    
    def containedIn(self, other):
        return self.hostPermUnion(other) == self
    
    def __lt__(self, other):
        return self.containedIn(other)

    def __eq__(self, other):
        return self.hostPerms == other.hostPerms
    def __contains__(self, other):
        return other[0] in self.hosts and self.hostPerms[other[0]] == other[1]

    def hostPermDiff(self, other):
        out = {}
        for host in other.hosts & self.hosts:
            if other.hostPerms[host] != self.hostPerms[host]:
                out[host] = max(other.hostPerms[host], self.hostPerms[host])
        for host in other.hosts - self.hosts:
            out[host] = other.hostPerms[host]
        for host in self.hosts - other.hosts:
            out[host] = self.hostPerms[host]
        return out

    def hostTrafficDiff(self,other):
        out = {}
        for host in set(other.hostTraffic.keys()) & set(self.hostTraffic.keys()):
            if other.hostTraffic[host] != self.hostTraffic[host]:
                out[host] = self.hostTraffic[host] - other.hostTraffic[host]
        for host in set(other.hostTraffic.keys()) - set(self.hostTraffic.keys()):
            out[host] = other.hostTraffic[host]
        return out
    
    def hostDiff(self, other):
        return self.hosts - other.hosts
    
    def hostIntersection(self, other):
        return self.hosts & other.hosts
    
    def hostPermUnion(self, other):
        out = self.hostPerms.copy()
        for host, perm in other:
            if out.get(host, -1) < perm:
                out[host] = perm
        return AttackNode(out, self.hostTraffic)

    def __len__(self):
        return len(self.hostPerms)

    def __hash__(self):
        return self._hash

    def __iter__(self):
        for host in self.hosts:
            yield host, self.hostPerms[host]
    
    def __repr__(self):
        return "an" + str(self.id)
        # def temp(host):
        #     return ":".join([repr(host), repr(self.hostPerms[host]), "{" + " ,".join(str(i) for i in  self.hostTraffic.get(host, set())) + "}"])
        # return "AttackNode({" + " ,".join(map(temp, self.hosts)) + "})"
