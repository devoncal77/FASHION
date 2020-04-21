import logging, sys, os
from sets import Set
from graph import Graph
from flow import Flow
from edgesData import EdgesData
class Network:
    def getLogDirectory(self):
        return "log"

    def getLogFilename(self):
        return "sdn.log"

    def initConfig(self):
        if self.debug:
            logging.basicConfig(stream=sys.stderr, level=logging.DEBUG) 
            try:
                os.mkdir(self.getLogDirectory())
            except OSError:
                pass
            logging.getLogger().addHandler(logging.FileHandler(self.getLogDirectory() +"/"+self.getLogFilename()))
        else:
            logging.basicConfig(stream=sys.stderr, level=logging.CRITICAL)
            logging.getLogger("gurobipy").setLevel(logging.CRITICAL) 
        

    def __init__(self, graph, routers, hosts, gateways, traffics, bad, good, cc, affected, memory,switchCap,compCost,topology={},debug=False,inputFile="N/A"):
        self.inputFile = inputFile
        self.debug = debug
        self.initConfig()
        self.Graph = graph
        self.R = routers
        self.H = hosts
        self.N = graph.V
        self.gateways = gateways
        self.traffics = traffics 
        self.flows = good + bad
        self.switchCap = switchCap
        self.compCost = compCost
        #self.affected = affected
        self.types = Set([f.t for f in self.flows])
        self.G = good
        self.B = bad
        self.nf = len(self.flows)
        # self.asrc = range(len(self.N),len(self.N)+self.nf)
        # self.asink = range(max(self.asrc)+1,max(self.asrc)+self.nf+1) 
        self.asrc = range(len(self.N),len(self.N)+1)
        self.asink = range(max(self.asrc)+1,max(self.asrc)+2) 
        logging.debug(self.N)
        logging.debug("asrc  =" + str(self.asrc))
        logging.debug("asink =" + str(self.asink))
        self.N = self.N + self.asrc + self.asink
        self.Graph.setVertices(self.N)
        logging.debug(self.N)
        self.cap = {}
        self.cost = {}
        for k in range(self.nf):
            self.flows[k].setSrc(self.asrc[0])
            self.flows[k].setSink(self.asink[0])
            self.Graph.addArc(self.asrc[0],self.flows[k].origin)
            self.Graph.addArc(self.flows[k].dest,self.asink[0])
            self.cost[(self.asrc[0],self.flows[k].origin)] = 0
            self.cap[(self.asrc[0],self.flows[k].origin)] = 1000000
            self.cost[(self.flows[k].dest,self.asink[0])] = 0
            self.cap[(self.flows[k].dest,self.asink[0])] = 1000000
        for ed in cc:
            self.cap[(int(ed.i),int(ed.j))] = ed.cap
            self.cost[(int(ed.i),int(ed.j))] = ed.cost
        self.cc = cc
        self.memory = memory
        self.topology = topology
        logging.debug(self.Graph)
        logging.debug("ARCS: " + str(self.Graph.arcs()))

    def __repr__(self):
        return "network(\n"+str(self.Graph)+"\nrouters:"+str(self.R)+"\nhosts:"+ \
        str(self.H)+"\nflows:"+str(self.flows)+"\nbad:" + str(self.B)+"\ngood:"+\
        str(self.G) +"\ncc:"+str(self.cc)+\
        "\ntypes:"+str(self.types)+")"

    @staticmethod
    def fromJson(dict,debug=False,inputFile="N/A"):
        g = Graph.fromJson(dict['graph'])
        bad = []
        if "bad" in dict:
            for k in dict['bad']:
                bad.append(Flow.fromJson(k))
        good = []
        for k in dict['good']:
            good.append(Flow.fromJson(k))
        cc = []
        for k in dict['cc']:
            cc.append(EdgesData.fromJson(k))
        compCost = {}
        if 'compCost' in dict:
            for host,costs in dict['compCost'].items():
                for lvl in range(len(costs)):
                    compCost[(int(host),lvl)] = costs[lvl]
        gateway = []
        if 'gateways' in dict:
            gateway = dict['gateways']
        switchCap = {}
        if 'switchCap' in dict:
            switchCap = dict['switchCap']
        return Network(g,dict['routers'],
            dict['hosts'],gateway,dict['traffics'],bad,good,cc,dict['affected'],
            dict['memory'],switchCap,compCost,dict['topology'],debug,inputFile)

    def pred(self,f,i):
        gp = self.Graph.pred(i)
        return gp if (i == f.origin) else gp.difference(Set([f.src]))
        
    def succ(self,f,i):
        gs = self.Graph.succ(i)
        return gs if (i == f.dest) else gs.difference(Set([f.sink]))
        
    def pred2(self,i):
        return self.Graph.pred(i)
    def succ2(self,i):
        return self.Graph.succ(i)

    def affected(self,i):
        return set()
        # return self.Graph.pred(i).union(self.Graph.succ(i))

