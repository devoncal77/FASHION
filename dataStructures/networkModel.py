from network import Network

class NetworkModel:
    def __init__(self, network):
        self.network = network
        self.debug = self.network.debug
        self.Graph = self.network.Graph
        self.R = self.network.R
        self.H = self.network.H
        self.N = self.network.N
        self.gateways = self.network.gateways
        self.traffics = self.network.traffics
        self.types = self.network.types
        self.flows = self.network.flows
        self.G = self.network.G
        self.B = self.network.B
        self.cap = self.network.cap
        self.cost = self.network.cost
        self.cc = self.network.cc
        self.memory = self.network.memory
        self.switchCap = self.network.switchCap
        self.compCost = self.network.compCost
        self.affected = self.network.affected
        self.topology = self.network.topology
        self.pred = self.network.pred
        self.pred2 = self.network.pred2
        self.succ = self.network.succ
        self.succ2 = self.network.succ2
        self.asrc = self.network.asrc
        self.asink = self.network.asink
        self.inputFile = self.network.inputFile
