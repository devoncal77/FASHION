import sys
import os
import json
import argparse
from sets import Set
import time
import logging
from itertools import permutations
from collections import defaultdict
from gurobipy import *
from dataStructures.networkModel import NetworkModel
from dataStructures.solution import Solution
from dataStructures.attackGraph import AttackNode

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
    def __init__(self, network, attackGraph=None,fw=1,sw=1,debug=False):
        NetworkModel.__init__(self,network)
        self.debug = debug
        self.functWeight = fw
        self.secWeight = sw
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
        self.reachable = self.m.addVars(list(self.AG.V),
                                    vtype=GRB.BINARY,
                                    name="reachable")
        self.active = self.m.addVars(list(self.AG.edges()),
                                    vtype=GRB.BINARY,
                                    name="active")
        self.aux = self.m.addVars(list(self.AG.edges()),
                                    vtype=GRB.BINARY,
                                    name="aux")
        self.compromised = self.m.addVars(list(self.AG.hostPerms.keys()),
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
        for vertex in self.AG.V:
            if vertex not in self.AG.pred or len(self.AG.pred[vertex]) == 0:
                continue
            self.m.addGenConstrOr(self.reachable[vertex], [self.aux[pred, vertex] for pred in self.AG.pred[vertex]])
        for edge in self.AG.edges():
            self.m.addGenConstrAnd(self.aux[edge], [self.reachable[edge[0]], self.active[edge]])
        for i, j in self.AG.exploitEdges:
            self.m.addConstr(self.active[i, j] == 1)  # could be == notPatched[exploit]
        for vertex in self.gateways:
            self.m.addConstr(self.reachable[AttackNode({vertex: 0}, {})] == 1)
        self.m.update()
        # cost of compromise constraints
        for i, j in self.AG.hostPerms.items():
            self.m.addGenConstrOr(self.compromised[i], [self.reachable[v] for v in j])
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
        for i, j in self.AG.networkEdges():
            newHost = j.hostDiff(i)
            # only two options for a network edge:
            # 1. adding entirely new host -- this means hostPerms will be different
            if newHost:  #i.hostPerms != j.hostPerms:
                assert len(newHost) == 1
                dstHost = next(iter(newHost))
                assert len(j.hostTraffic[dstHost]) == 1
                newType = next(iter(j.hostTraffic[dstHost]))
            # 2. just adding add'l traffic type for one host -- this means hostPerms will be the same
            else:
                # find the host,newType pair
                dstHost, newType = next(iter(j.hostTrafficDiff(i).items()))
                newType = next(iter(newType))

            if int(dstHost) in self.gateways:
                self.m.addConstr(self.active[i,j] == 0)
            else:
                self.m.addGenConstrOr(self.active[i,j], [self.conn[int(host), int(dstHost), newType] for host in i.hosts if host != dstHost])

        # objective
        self.m.update()
        # alpha = [100,20,1,5,20,10,1]
        alpha = [10,1,1,4,1,1]

        self.functScore = self.m.addVar(vtype=GRB.CONTINUOUS, lb=-GRB.INFINITY, name="functScore")
        self.secScore = self.m.addVar(vtype=GRB.CONTINUOUS, lb=-GRB.INFINITY, name="secScore")

        self.m.addConstr(self.functScore == quicksum(-self.p[f,f.dest,f.sink]*f.value for f in self.G) * alpha[0] 
                                    + quicksum(self.p[f,i,j] * self.cost[i,j] for (f,i,j) in self.p) * alpha[1]
                                    + quicksum(self.wt) * alpha[2] 
                                    + quicksum(self.w) * alpha[3]
                                    + quicksum(self.hasW) * alpha[4]
                                    )
        self.m.addConstr(self.secScore == quicksum(self.compromised[i]*self.compCost[i] for i in self.compromised) * alpha[5])

        self.m.setObjective(self.functWeight * self.functScore + self.secWeight * self.secScore, GRB.MINIMIZE)
        self.m.update()
        end = time.time()
        logging.debug("time to build the model : "+str(end-start))
        self.buildTime = (end - start)

    def render(self, verbose = False):
        from graphviz import Digraph
        dot = Digraph()
        trafficColors = {1: 'black', 2:'blue', 3:'purple'}
        if verbose:
            def label(node):
                return "\n".join(str(host) + "|" + str(node.hostPerms[host]) +"|{"+ " ,".join(map(str, node.hostTraffic.get(host, set()))) + "}" for host in node.hosts)
            reachable = self.m.getAttr('x', self.reachable)
            reachable = set(filter(lambda k : reachable[k] != 0.0,reachable.keys()))
            for node in self.AG.V:
                if node in reachable:
                    dot.node(label(node), color="green")
                else:
                    dot.node(label(node))
            active = self.m.getAttr('x',self.active)
            active = set(filter(lambda k : active[k] != 0.0,active.keys()))
            for start, stop in self.AG.networkEdges():
                if (start, stop) in active:
                    dot.edge(label(start), label(stop), style="solid")
                else:
                    dot.edge(label(start), label(stop), style="dashed")
            for start, stop in self.AG.exploitEdges:
                dot.edge(label(start), label(stop), color="Red")
        else:
            def label(node):
                return repr(node)
            for node in self.AG.hostPerms.keys():
                if node[0] in self.gateways:
                    dot.node(label(node), shape="square")
                else:
                    dot.node(label(node))
            conn = self.m.getAttr('x',self.conn)
            conn = set(filter(lambda k : conn[k] != 0.0,conn.keys()))
            # for start, stop in permutations(filter(lambda i: i[1] == 0, self.AG.hostPerms.keys()), 2):
            #     for t in self.traffics:
            #         if stop[0] in self.gateways:
            #             continue
            #         if len(self.stFlows[start[0], stop[0], t]) == 0:
            #             continue
            #             # dot.edge(label(start), label(stop), style="invis")
            #         elif (start[0],stop[0], t) in conn:
            #             dot.edge(label(start), label(stop), style="solid", color=trafficColors[t])
            #         else:
            #             dot.edge(label(start), label(stop), style="dashed", color=trafficColors[t])
            for src, dst, t in self.conn.keys():
                if dst in self.gateways:
                    continue
                if len(self.stFlows[src, dst, t]) == 0:
                    continue
                    # dot.edge(label(start), label(stop), style="invis")
                elif (src, dst, t) in conn:
                    dot.edge(label((src,0)), label((dst, 0)), style="solid", color=trafficColors[t])
                else:
                    dot.edge(label((src, 0)), label((dst, 0)), style="dashed", color=trafficColors[t])
            for exploitIndex, exploit in enumerate(self.AG._exploits):
                label = "Exploit " + str(exploitIndex)
                dot.node(label, color="Red", shape="diamond")
                dot.edge(label, repr(exploit.outcome), color="Red")
                temp = { i:0 for i in exploit.networkPrereqs.keys()}
                temp.update(exploit.prereqs)
                for prereq in temp.items():
                    dot.node(repr(prereq))
                    dot.edge(repr(prereq), label, color="Red")
        dot.node("#nodes = " + str(len(self.AG.V)))
        dot.node("#edges = " + str(sum(len(i) for i in self.AG.succ.values())))
        dot.render("test-output.svg", view=True, cleanup=True, format="svg")

    def run(self,render=False):
        solveStart = time.time()
        self.m.optimize(cut_counter)
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
                self.render(verbose=False)
            return Solution(self,self.AG,pv,bv,wv,wtv,self.m.objVal,fs,ss,var=self.m.NumVars,cst=self.m.NumConstrs,nodesBB=self.m.NodeCount,iter=self.m.IterCount,status='OPTIMAL')
        return Solution(self,self.AG,{},{},{},{},0,0,0,var=self.m.NumVars,cst=self.m.NumConstrs,nodesBB=self.m.NodeCount,iter=self.m.IterCount,status='INFEASIBLE')
        






