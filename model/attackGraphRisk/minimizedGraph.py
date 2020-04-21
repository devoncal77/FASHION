import sys
import os
import json
from sets import Set
import time
import logging
from itertools import permutations
from collections import defaultdict
from gurobipy import *
from dataStructures.networkModel import NetworkModel
from dataStructures.solution import Solution
from dataStructures.booleanGraph import BooleanGraph, ExploitNode, HostNode

def cut_counter(model, where):
        cut_names = {
            'Clique:', 'Cover:', 'Flow cover:', 'Flow path:', 'Gomory:', 
            'GUB cover:', 'Inf proof:', 'Implied bound:', 'Lazy constraints:', 
            'Learned:', 'MIR:', 'Mod-K:', 'Network:', 'Projected Implied bound:', 
            'StrongCG:', 'User:', 'Zero half:'}
        if where == GRB.Callback.MESSAGE:
            # Message callback
            msg = model.cbGet(GRB.Callback.MSG_STRING)
            if any(name in msg for name in cut_names):
                splitted = msg.split(':')
                model._cut_count += int(splitted[1])

class AttackGraphModel(NetworkModel):
    def __init__(self, network, attackGraph=None,fw=1,sw=1,widthW=1.0,depthW=1.0,debug=False):
        NetworkModel.__init__(self,network)
        self.debug = debug
        self.functWeight = fw
        self.secWeight = sw
        self.widthW = widthW
        self.depthW = depthW
        if attackGraph:
            self.AG = attackGraph
        else:
            self.createAG()

    def createAG(self):
        raise NotImplementedError

    def initModel(self,timeout):
        self.m = Model("attackGraphModel")
        if timeout > 0:
            self.m.setParam('TimeLimit',timeout)
        self.m._cut_count = 0
        if not self.debug: 
            self.m.setParam( 'OutputFlag', False )

    def makeModel(self, timeout=0):
        start = time.time()
        self.initModel(timeout)
        # networkFlow vars
        self.p = self.m.addVars([(f,i,j) for f in self.flows 
                                for (i,j)  in self.Graph.arcs() 
                                ],vtype=GRB.BINARY,name="p")
        self.blocked = self.m.addVars([(f,i)    for f in self.flows 
                                for i in self.R],vtype=GRB.BINARY,name="blocked")
        self.w = self.m.addVars([(f,i)  for f in self.flows for i in self.R],vtype=GRB.BINARY,name="w")
        self.wt = self.m.addVars([(t,i)     for t in self.types for i in self.R],vtype=GRB.BINARY,name="wt")
        connectionPairs = [(i,j) for (i,j) in permutations(self.H,2)] + [(i,j) for i in self.gateways for j in self.H]
        self.conn = self.m.addVars([(i,j,t) for (i,j) in connectionPairs for t in self.traffics],
                                    vtype=GRB.BINARY,
                                    name="conn")
        # attack graphs vars
        self.reachable = self.m.addVars(list(self.AG.networkNodes | self.AG.exploitNodes),
                                    vtype=GRB.BINARY,
                                    name="reachable")
        self.active = self.m.addVars(list(self.AG.edges()),
                                    vtype=GRB.BINARY,
                                    name="active")
        self.aux = self.m.addVars(list(self.AG.edges()),
                                    vtype=GRB.BINARY,
                                    name="aux")
        self.compromised = self.m.addVars(list({(node.host, node.permission) for node in self.AG.networkNodes}),
                                            vtype=GRB.BINARY,
                                            name="compromised")
        # other vars
        self.hasW = self.m.addVars([i for i in self.R], vtype=GRB.BINARY, name="hasW")
        self.m.update()
        logging.debug(self.Graph)
        # network flow constraints
        for f in self.flows:
            self.m.addConstr(self.p[f,f.src,f.origin] == 1)     
            self.m.addConstr(self.p[f,f.dest,f.sink] <= 1)      
            logging.debug("flow (%d,%d) - [%d,%d]" % (f.origin, f.dest,f.src,f.sink))
            for i in Set(self.R):
                logging.debug("Router: %d" % (i))
                logging.debug("\tpred:" + str(self.pred(f,i)))
                logging.debug("\tsucc:" + str(self.succ(f,i)))
                getsFlow = self.m.addVar(vtype=GRB.BINARY)
                blocksFlowByType = self.m.addVar(vtype=GRB.BINARY)
                self.m.addConstr(getsFlow <= quicksum(self.p[f,j,i] for j in self.pred(f,i)))
                for j in self.pred(f,i):
                    self.m.addConstr(getsFlow >= self.p[f,j,i])
                self.m.addConstr(blocksFlowByType >= getsFlow + self.wt[f.t,i] - 1)
                self.m.addConstr(blocksFlowByType <= getsFlow)
                self.m.addConstr(blocksFlowByType <= self.wt[f.t,i])
                self.m.addConstr(self.blocked[f,i] >= self.w[f,i])
                self.m.addConstr(self.blocked[f,i] >= blocksFlowByType) # and exists(j in pred(i) : p[f,j,i])
                self.m.addConstr(self.blocked[f,i] <= self.w[f,i] + blocksFlowByType)
                self.m.addConstr(quicksum(self.p[f,j,i] for j in self.pred(f,i)) ==
                            quicksum(self.p[f,i,j] for j in self.succ(f,i)) + self.blocked[f,i] #+ w[f,i]
                            )
            for i in Set(self.H):
                logging.debug("Host: %d" % (i))
                logging.debug("\tH-pred:" + str(self.pred(f,i)))
                logging.debug("\tH-succ:" + str(self.succ(f,i)))
                self.m.addConstr(quicksum(self.p[f,j,i] for j in self.pred(f,i)) ==
                            quicksum(self.p[f,i,j] for j in self.succ(f,i)))
                # prevent non-src/dest hosts from forwarding traffic
                if i != f.origin and i != f.dest:
                    for j in self.succ(f, i):
                        self.m.addConstr(self.p[f,i,j] == 0)
                elif i == f.dest:  # host can forward only to sink
                    for j in self.succ(f,i):
                        if j != f.sink:
                            self.m.addConstr(self.p[f,i,j] == 0)
        # Capacity on LINKS             
        for i in self.R:
            for j in self.pred2(i):
                if (j,i) in self.cap:
                    cap = self.cap[(j,i)]
                else:
                    cap = 1000000
                self.m.addConstr(quicksum(self.p[e,j,i]*e.flow for e in self.flows) <= cap)
            for j in self.succ2(i):
                if (i,j) in self.cap:
                    cap = self.cap[(i,j)]
                else:
                    cap = 1000000
                self.m.addConstr(quicksum(self.p[e,i,j]*e.flow for e in self.flows) <= cap)
        # Capacity on ROUTERS
        for i in self.R:
            self.m.addConstr(quicksum(self.p[f,j,i] * f.flow for f in self.flows for j in self.pred2(i)) +
                        quicksum(self.p[f,i,j] * f.flow for f in self.flows for j in self.succ2(i))
                        <= self.switchCap[str(i)])
        # Require firewall for bad flows
        for b in self.B:
            self.m.addConstr(quicksum(self.w[b,i] + self.wt[b.t,i] for i in self.R) >= 1)
        # Count number of unique devices deploying a firewall
        for i in self.R:
            for f in self.flows:
                self.m.addConstr(self.hasW[i] >= self.w[f,i])
            for t in self.types:
                self.m.addConstr(self.hasW[i] >= self.wt[t,i])
            self.m.addConstr(self.hasW[i] <= quicksum(self.w[f,i] for f in self.flows) + quicksum(self.wt[t,i] for t in self.types))
        # Prevent good flow specific firewalls
        for i in self.R:
            for f in self.G:
                self.m.addConstr(self.w[f,i] == 0)
        # Attack graph constraints
        for vertex in self.AG.networkNodes:
            if vertex not in self.AG.pred or len(self.AG.pred[vertex]) == 0:
                continue
            self.m.addGenConstrOr(self.reachable[vertex], [self.aux[pred, vertex] for pred in self.AG.pred[vertex]])
        for vertex in self.AG.exploitNodes:
            if vertex not in self.AG.pred or len(self.AG.pred[vertex]) == 0:
                continue
            self.m.addGenConstrAnd(self.reachable[vertex], [self.aux[pred, vertex] for pred in self.AG.pred[vertex]])
        for edge in self.AG.edges():
            self.m.addGenConstrAnd(self.aux[edge], [self.reachable[edge[0]], self.active[edge]])
        for i, j in self.AG.exploitEdges:
            self.m.addConstr(self.active[i, j] == 1)  # could be == notPatched[exploit]
        for vertex in self.AG.gateways:
            self.m.addConstr(self.reachable[vertex] == 1)
        self.m.update()
        # cost of compromise constraints
        for hp, bucket in self.AG.hostPerms().items():
            assert(len(bucket) > 0)
            self.m.addGenConstrOr(self.compromised[hp], [self.reachable[node] for node in bucket])
        # create src-dst flow dict
        self.stFlows = { (i,j,t):[] for i,j,t in self.conn }
        for f in self.flows:
            if f.dest not in self.gateways:
                self.stFlows[f.origin, f.dest, f.t].append(f)
        for i,j,t in self.conn:
            if len(self.stFlows[i,j,t]) > 0:
                pVars = [self.p[f,j,f.sink] for f in self.stFlows[i,j,t]]
                self.m.addGenConstrOr(self.conn[i,j,t], pVars)
            else:
                self.m.addConstr(self.conn[i,j,t] == 0)
        # link attackGraph active vars with network conn vars
        for i, j in self.AG.networkEdges:
            # TODO: Fix for traffic types
            dstHost = j.host
            newType = j.traffic
            if i.host == j.host:
                continue
            if int(dstHost) in self.gateways:
                self.m.addConstr(self.active[i,j] == 0)
            else:
                self.m.addConstr(self.active[i,j] == self.conn[int(i.host), int(dstHost), newType])

        # objective
        self.m.update()
        # alpha = [100,20,1,5,20,10,1]
        alpha = [10,1,1,4,1,1]
        self.functScore = self.m.addVar(vtype=GRB.CONTINUOUS, lb=-GRB.INFINITY, name="functScore")
        self.secScore = self.m.addVar(vtype=GRB.CONTINUOUS, lb=-GRB.INFINITY, name="secScore")
        self.m.addConstr(self.functScore == quicksum(-self.p[f,f.dest,f.sink]*f.value for f in self.G) * alpha[0] 
                                        + quicksum(self.p[f,i,j] * self.cost[i,j] for (f,i,j) in self.p) * alpha[1]
                                        )
        self.m.addConstr(self.secScore == quicksum(self.compromised[i]*self.compCost[i] for i in self.compromised) * alpha[5]
                                        + quicksum(self.wt) * alpha[2] 
                                        + quicksum(self.w) * alpha[3]
                                        + quicksum(self.hasW) * alpha[4]
                                        )
        self.m.setObjective((self.functWeight * self.functScore) + (self.secWeight * self.secScore), GRB.MINIMIZE)
        self.m.update()
        end = time.time()
        logging.debug("time to build the model : "+str(end-start))
        self.buildTime = (end - start)

    def render(self):
        from graphviz import Digraph
        cid = 0
        dot = Digraph()
        trafficColors = {1: 'black', 2:'blue', 3:'purple'}
        def label(node):
            return repr(node)
        for node in self.AG.hostPerms().keys():
            if node[0] in self.gateways:
                dot.node(label(node), shape="square")
            else:
                dot.node(label(node))
        conn = self.m.getAttr('x',self.conn)
        conn = set(filter(lambda k : conn[k] != 0.0,conn.keys()))
        jumpnodes = {}
        for src, dst, t in self.conn.keys():
            if dst in self.gateways:
                continue
            if len(self.stFlows[src, dst, t]) == 0:
                continue
                # dot.edge(label(start), label(stop), style="invis")
            elif (src, dst, t) in conn:
                if (src, dst) not in jumpnodes:
                    dot.node(str(cid),label="NET", color="SpringGreen", shape="polygon")
                    jumpnodes[(src,dst)] = cid
                    cid+=1
                n = jumpnodes[(src, dst)]
                dot.edge(label((src,0)), str(n), style="solid", color=trafficColors[t])
                dot.edge(str(n), label((dst, 0)), style="solid", color=trafficColors[t])
            else:
                if (src, dst) not in jumpnodes:
                    dot.node(str(cid),label="NET", color="SpringGreen", shape="polygon")
                    jumpnodes[(src,dst)] = cid
                    cid+=1
                n = jumpnodes[(src, dst)]
                dot.edge(label((src, 0)), str(n), style="dashed", color=trafficColors[t])
                dot.edge(str(n), label((dst, 0)), style="dashed", color=trafficColors[t])
        for exploitIndex, exploit in enumerate(self.AG.exploitNodes):
            label = "Exploit " + str(exploitIndex)
            dot.node(label, color="Red", shape="diamond")
            dot.edge(label, repr((exploit.outcome.host, exploit.outcome.permission)), color="Red")
            for prereq in exploit.prereqs:
                if prereq.traffic:
                    fromLabel = repr((prereq.host, 0))
                else:
                    fromLabel = repr((prereq.host, prereq.permission))
                dot.node(fromLabel)
                dot.edge(fromLabel, label, color="Red")
        # dot.node("#nodes = " + str(len(self.AG.networkNodes) + len(self.AG.exploitNodes)))
        # dot.node("#edges = " + str(sum(len(i) for i in self.AG.succ.values())))
        dot.render("test-output.svg", view=True, cleanup=True, format="svg")

    def run(self,render=True):
        solveStart = time.time()
        self.m.optimize()
        solveEnd = time.time()
        self.solveTime = solveEnd - solveStart
        if self.m.status == GRB.status.OPTIMAL:
            logging.debug('\nCost:'+ str(self.m.objVal))
            pv = self.m.getAttr('x',self.p)
            bv  = self.m.getAttr('x',self.blocked)
            wv = self.m.getAttr('x',self.w)
            wtv = self.m.getAttr('x',self.wt)
            hasWv = self.m.getAttr('x',self.hasW)
            conn = self.m.getAttr('x',self.conn)
            comp = self.m.getAttr('x',self.compromised)
            reach = self.m.getAttr('x',self.reachable)
            active = self.m.getAttr('x',self.active)
            fs = self.functScore.x
            ss = self.secScore.x
            maxVal = sum([f.value for f in self.G])
            gainedVal = sum([self.p[f,f.dest,f.sink].x * f.value for f in self.G])
            lostVal = sum([(1 - self.p[f,f.dest,f.sink].x) * f.value for f in self.G])
            nbCompStates = sum([self.compromised[i,j].x for i,j in self.compromised if i not in self.gateways])
            compCostVal = sum([self.compromised[i].x * self.compCost[i] for i in self.compromised])
            logging.debug('\n\tp  = ' + str(filter(lambda k : pv[k] != 0.0,pv.keys())))
            logging.debug('\n\tb  = ' + str(filter(lambda k : bv[k] != 0.0,bv.keys())))
            logging.debug('\n\tw = ' + str(filter(lambda k : wv[k] != 0.0,wv.keys())))
            logging.debug('\n\twt = ' + str(filter(lambda k : wtv[k] != 0.0,wtv.keys())))
            logging.debug('\n\thasW = ' + str(filter(lambda k : hasWv[k] != 0.0,hasWv.keys())))
            logging.debug('\n\tconn = ' + str(filter(lambda k : conn[k] != 0.0,conn.keys())))
            logging.debug('\n\tcomp = ' + str(filter(lambda k : comp[k] != 0.0,comp.keys())))
            logging.debug('\n\treach = ' + str(filter(lambda k : reach[k] != 0.0,reach.keys())))
            logging.debug('\n\tactive = ' + str(filter(lambda k : active[k] != 0.0,active.keys())))
            if render:
                self.render()

            return Solution(self,self.AG,pv,bv,wv,wtv,maxVal,gainedVal,lostVal,nbCompStates,compCostVal,self.m.objVal,fs,ss,var=self.m.NumVars,cst=self.m.NumConstrs,nodesBB=self.m.NodeCount,iter=self.m.IterCount,status='OPTIMAL')
        return Solution(self,self.AG,{},{},{},{},0,0,0,0,0,0,0,0,var=self.m.NumVars,cst=self.m.NumConstrs,nodesBB=self.m.NodeCount,iter=self.m.IterCount,status='INFEASIBLE')
        






