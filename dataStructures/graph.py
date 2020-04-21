from flow import Flow
from sets import Set

class Graph:
    def __init__(self,nv,e):
        self.V = range(nv)
        self.E = e
        self.p = {}
        self.s = {}
        for i in self.V:
            self.p[i] = Set(filter(lambda k: i in e[k],e.keys()))
            self.s[i] = Set(self.E[i])
            self.p[i] = self.p[i].union(self.s[i])
            self.s[i] = self.p[i].union(self.s[i])

    def setVertices(self,vc):
        self.V = vc
        for v in vc:
            if not (v in self.p):
                self.p[v] = Set([])
                self.s[v] = Set([])
    def addArc(self,s,d):
        if s in self.s.keys():
            self.s[s].add(d)
        else:
            self.s[s] = Set([d])
        if d in self.p.keys():
            self.p[d].add(s)
        else:
            self.p[d] = Set([s])
    def pred(self,i):
        return self.p[i]
        #return self.p[i].union(Set(self.E[i]))
    def succ(self,i):
        return self.s[i]
        #return self.p[i].union(Set(self.E[i]))
    def arcs(self):
        arcs = Set([])
        for i in self.V:
            for j in self.s[i]:
                arcs.add((i,j))
        return arcs
    def size(self):
        return(len(self.V),sum(map(len,self.E.values())))

    @staticmethod
    def fromJson(dict):
        ed = {}
        for k in dict['edges'].keys():
            ed[int(k)] = dict['edges'][k]
        return Graph(dict['size'],ed)
    def __repr__(self):
        return "g(" + str(self.V) + "," + str(self.E) \
        + ",\nPRED:" + str(self.p) + ",\nSUCC:" + str(self.s) + ")"
