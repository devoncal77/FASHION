from  gurobipy import GRB

class Solution:
    def __init__(self,net=None,AG=None,pv={},bv={},wv={},wtv={},maxVal=0,gainedVal=0,lostVal=0,nbCompStates=0,compCostVal=0,objVal=0.0,functScore=0,secScore=0,depthScore=0,widthScore=0,var=0,cst=0,iter=0,cuts=0,name="",nodesBB=0,status=None,check=False):
        self.net = net
        self.AG = AG
        self.pv = pv
        self.bv = bv
        self.wv = wv
        self.wtv = wtv
        self.maxVal = maxVal
        self.gainedVal = gainedVal
        self.lostVal = lostVal
        self.nbCompStates = nbCompStates
        self.compCostVal = compCostVal
        self.objVal = objVal
        self.functScore = functScore
        self.secScore = secScore
        self.depthScore = depthScore
        self.widthScore = widthScore
        self.var = var 
        self.cst = cst
        self.check = check
        self.name = name
        self.cuts = cuts
        self.status = self.net.m.status
        self.nbiter = iter
        self.nodesBB = nodesBB
        self.riskMeasure = 0.0
        self.riskTime = 0.0
        self.SCC = 0

    def blocked(self):
        return self.blockedB() # + self.blockedG()
    def blockedG(self):
        return filter(lambda k : self.bv[k] != 0.0,self.bv.keys())
    def blockedB(self):    
        return filter(lambda k : self.bv[k] != 0.0,self.bv.keys())
    def flows(self):
        return filter(lambda k : self.pv[k] != 0.0,self.pv.keys())
    def FW(self):
        return map(lambda (f,r): r,filter(lambda k : self.wv[k] != 0.0,self.wv.keys()))
    def FWT(self):
        return filter(lambda k : self.wtv[k] != 0.0,self.wtv.keys())
    def __repr__(self):
        stats = ""
        if self.AG :
            stats = "%s, %f, %f, %f, %d, %d, %d, %d, %d, %d-%d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %f, %f, %f, %f, %d, %d, %d, %d,%f,%d, %s" \
            %(self.net.inputFile, self.AG.buildTime , self.net.buildTime, self.net.solveTime, self.AG.nbNodes(), self.AG.nbEdges(),\
            self.AG.avgDeg(), self.AG.avgDegIn(), self.AG.avgDegOut(), self.AG.rangeSizeExploits()[0],self.AG.rangeSizeExploits()[1] , self.AG.nbExploits(), \
            self.AG.nbPermissions(), len(self.net.H), len(self.net.R), len(self.net.flows), len(self.blocked()),len(self.FW()),len(self.FWT()),len(self.net.traffics), \
            self.net.m.NumVars, self.net.m.NumConstrs, self.net.m.IterCount, self.net.m._cut_count, self.net.m.NodeCount, \
            self.maxVal, self.gainedVal, self.lostVal, self.nbCompStates, self.compCostVal, self.net.functWeight, self.net.secWeight, \
            self.functScore, self.secScore, self.depthScore, self.widthScore, self.net.m.objVal if self.net.m.status == GRB.status.OPTIMAL else 0, self.riskMeasure, self.riskTime, self.SCC,self.net.m.status)
        else:
            stats = "%s, %f, %f, %f, %d, %d, %d, %d, %d, %d-%d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %f, %f, %f, %f, %d, %d, %d, %d,%f,%d, %s" \
            %(self.net.inputFile, 0, self.net.buildTime, self.net.solveTime, 0, 0, 0,\
            0, 0, 0, 0, 0, len(self.net.H), len(self.net.R), len(self.net.flows), len(self.blocked()),len(self.FW()),len(self.FWT()), len(self.net.traffics), \
            self.net.m.NumVars, self.net.m.NumConstrs, self.net.m.IterCount, self.net.m._cut_count, self.net.m.NodeCount, self.net.m.objVal if self.net.m.status == GRB.status.OPTIMAL else 0, self.riskMeasure, self.riskTime,self.SCC,self.net.m.status)
        
        return stats 

    @staticmethod
    def format():
        return "name,#nodes,#edges,#routers,#hosts,#G,#B,#F,#blockedG,#blockedB,#fw,#fwT,#variables,#constraintes,#iter,#cuts,#nodesBB,objVal,Time Building, Time Resolution,Status,check,"

    def writeStats(self, fname=None,printHeader=False):
        if not isinstance(fname,str):
            from time import localtime
            from time import asctime
            fname = asctime(localtime()) + ".csv"

        # header = "inputFile, AGbuildTime, modelBuildTime, modelSolveTime, AGnodes, AGedges, AGdeg, AGdegIn, AGdegOut, " + \
        #          "rangeExploits, nbExploits, nbPermissions, nbHosts, nbSwitches, nbFlows, nbBlocked, nbFW, nbFWT, nbTrafficTypes, " + \
        #          "nbVars, nbConstraints, nbIterations, cutCount, nbBBnodes, objVal, status"
        
        stats = self.__repr__() 

        # if self.AG :
        #     stats = "%s, %f, %f, %f, %d, %d, %d, %d, %d, %d-%d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %s" \
        #         %(self.net.inputFile, self.AG.buildTime , self.net.buildTime, self.net.solveTime, self.AG.nbNodes(), self.AG.nbEdges(),\
        #         self.AG.avgDeg(), self.AG.avgDegIn(), self.AG.avgDegOut(), self.AG.rangeSizeExploits()[0],self.AG.rangeSizeExploits()[1] , self.AG.nbExploits(), \
        #         self.AG.nbPermissions(), len(self.net.H), len(self.net.R), len(self.net.flows), len(self.blocked()),len(self.FW()),len(self.FWT()),len(self.net.traffics), \
        #         self.net.m.NumVars, self.net.m.NumConstrs, self.net.m.IterCount, self.net.m._cut_count, self.net.m.NodeCount, \
        #         self.net.m.objVal if self.net.m.status == GRB.status.OPTIMAL else 0, self.functScore, self.secScore, self.net.m.status)
        # else:
        #     stats = "%s, %f, %f, %f, %d, %d, %d, %d, %d, %s, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %s" \
        #     %(self.net.inputFile, 0, self.net.buildTime, self.net.solveTime, 0, 0, 0,\
        #     0, 0, 0, 0, 0, len(self.net.H), len(self.net.R), len(self.net.flows), len(self.blocked()),len(self.FW()),len(self.FWT()), len(self.net.traffics), \
        #     self.net.m.NumVars, self.net.m.NumConstrs, self.net.m.IterCount, self.net.m._cut_count, self.net.m.NodeCount, \
        #     self.net.m.objVal if self.net.m.status == GRB.status.OPTIMAL else 0, self.functScore, self.secScore, self.net.m.status)


        with open(fname,"a") as f:
            f.write(stats)
            f.write("\n")

        # print "objval:%d" %(self.net.m.objVal)
