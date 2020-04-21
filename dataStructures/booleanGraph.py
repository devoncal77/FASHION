from time import time
from collections import defaultdict
from itertools import permutations
class BooleanGraph:
    def __init__(self, networkNodes, exploitNodes, gateways, succ, pred, networkEdges, exploitEdges, buildTime = 0):
        # gateways is a subset of hosts
        # exploits and hosts are mutually exclusive 
        self.networkNodes = networkNodes
        self.exploitNodes = exploitNodes
        self.networkEdges = networkEdges
        self.exploitEdges = exploitEdges
        self.gateways = gateways
        self.succ = dict(succ)
        self.pred = dict(pred)
        # These should probably be removed
        self.buildTime = buildTime
    
    def hostPerms(self):
        out = defaultdict(set)
        for node in self.networkNodes:
            out[node.host,node.permission].add(node)
        return out

    def edges(self):
        for edge in self.networkEdges:
            yield edge
        for edge in self.exploitEdges:
            yield edge
    def nodes(self):
        for node in self.networkNodes:
            yield node
        for node in self.exploitNodes:
            yield node

    # Exploits only ever have one outgoing edge
    def succExploitEdge(self, exploit):
        return (exploit, next(iter(self.succ[exploit])))

    # These should be full names
    def nbNodes(self):
        return len(self.networkNodes) + len(self.exploitNodes)
    
    def nbEdges(self):
        return len(self.exploitEdges) + len(self.networkEdges)
    
    def avgDeg(self):
        return 0
    
    def avgDegIn(self):
        return 0
    def avgDegOut(self):
        return 0
    def rangeSizeExploits(self):
        return (self.minSzE,self.maxSzE)
    def nbExploits(self):
        return len(self.exploitNodes)
    def nbPermissions(self):
        return self.maxPl

    @staticmethod
    def fromJson(dict):
        buildStart = time()
        networkNodes = set()
        gateways = set()
        exploits = set()
        succ = defaultdict(set)
        pred = defaultdict(set)
        exploitEdges = set()
        networkEdges = set()
        entryNodes = set()
        trafficTypes = dict["traffics"]
        minSz = 1000000
        maxSz = 0
        maxPl = 0
        for h, lvls in dict["permissionLevels"].items():
            maxPl = max(maxPl,lvls)
            h = int(h)
            if h in dict["gateways"]:
                continue
            for traffic in trafficTypes:
                for lvl in range(lvls):
                    if lvl == 0:
                        node = HostNode(h,0,traffic=traffic)
                        entryNodes.add(node)
                    else:
                        node = HostNode(h, lvl)
                    networkNodes.add(node)
        
        for g in dict["gateways"]:
            node = HostNode(g, isGateway=True)
            networkNodes.add(node)
            gateways.add(node)
            entryNodes.add(node)
        
        for i, j in permutations(entryNodes, 2):
            if j in gateways:
                continue
            if i.host == j.host:
                continue
            succ[i].add(j)
            pred[j].add(i)
            networkEdges.add((i, j))

        for e in dict["exploits"]:
            minSz = min(minSz,len(e["prereq"]["permissions"]))
            maxSz = max(maxSz,len(e["prereq"]["permissions"]))
            prereqs = {HostNode(host, perm) for host, perm in e["prereq"]["permissions"] if perm != 0}
            prereqs |= {HostNode(host, 0, traffic=traffic) for host, traffics in e["prereq"]["network"] for traffic in traffics}
            prereqs = frozenset(prereqs)
            outcome = HostNode(*e["outcome"]) # Assuming that the outcome is never a gateway
            node = ExploitNode(prereqs, outcome, e["prob"])
            exploits.add(node)
            for prereq in prereqs:
                succ[prereq].add(node)
                pred[node].add(prereq)
                exploitEdges.add((prereq, node))
            succ[node].add(outcome)
            pred[outcome].add(node)
            exploitEdges.add((node, outcome))
        res = BooleanGraph(networkNodes, exploits, gateways, succ, pred, networkEdges, exploitEdges, buildTime=time()-buildStart)
        res.maxPl = maxPl
        res.minSzE = minSz
        res.maxSzE = maxSz
        return res


class HostNode:
    def __init__(self, host, permission=0, isGateway=False, traffic=None):
        assert(int(host) == host)
        assert(int(permission) == permission)
        self.host = host
        self.permission = permission
        self.isGateway = isGateway
        self.traffic = traffic
        self._hash = None
        if isGateway and (traffic is not None or permission != 0):
            raise AttributeError("Gateways require minimal permision and traffic")
        if traffic is not None and permission != 0:
            raise AttributeError("Perrmission must be 0 when traffic is not None")
        if permission == 0 and traffic is None and not isGateway:
            raise AttributeError("permission 0 implies having a traffic type")
    
    def __eq__(self, other):
        try:
            return self.host == other.host and self.permission == other.permission and self.isGateway == other.isGateway and self.traffic == other.traffic
        except:
            return False

    def __hash__(self):
        # return -1
        if self._hash is None:
            # hashing None is not consistent with gurobi?
            self._hash = hash((self.host, self.permission, self.isGateway, -1 if self.traffic is None else self.traffic))
        return self._hash
    
    def __repr__(self):
        # return ", ".join(str(i) for i in [self.host, self.permission, self.isGateway, self.traffic, self._hash])
        if self.isGateway:
            return "HostNode("+str(self.host) + ",gateway)"
        if self.traffic:
            return "HostNode("+str(self.host) + ",T" + str(self.traffic) + ")"
        return "HostNode("+str(self.host) + "," + str(self.permission) + ")"
    
class ExploitNode:
    def __init__(self, prereqs, outcome, probability):
        self.prereqs = prereqs # Set[HostNode]
        self.outcome = outcome # HostNode
        self.probability = probability # float
        self._hash = None
    
    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.prereqs, self.outcome, self.probability))
        return self._hash
    
    def __repr__(self):
        return "ExploitNode(" + str(self.prereqs) + "->" + str(self.outcome) + ")"
