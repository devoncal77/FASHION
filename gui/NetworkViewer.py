"""
Nice visualisation of a network using graphviz.

"""

from graphviz import Digraph as gdot
from Utils import *
import os

DROP = enum(ALL='all',FLOW='flow',TRAFFIC='traffic')


class NetworkViewer:
	directory = "./images/"
	def test(self):
		print "NetworkViewer"
	def __init__(self,net,debug=False,nbT=2):
		self.debug = debug
		self.net = net
		self.color = {"firewall":"lightgrey", "firewallT": "lightslategray", "firewallAll": "dimgray", \
			"affected":"crimson","source":"lightblue","sink":"purple","good":"green","bad":"blue",\
			"blocked":"black"}
		self.shape = {"host":'square',"routers":'circle',"source":'doublecircle',"sink":'doublecircle'}
		self.firewall = set()
		self.firewallT = {}
		self.firewallAll = set()
		self.affected = []
		self.edges = {}
		tc = {}
		col = [None,"black","blue","purple"]
		indexC = 0
		for t in range(nbT+1):
			tc[t] = col[indexC]
			indexC = (indexC + 1) % len (col)
		self.color["traffics"] = tc
		self.traffics = {}
		try: 
			os.makedirs(NetworkViewer.directory)
		except OSError:
			pass
	def setFirewallColor(self,color):
		self.color["firewall"] = color
	def setFirewallTColor(self,color):
		self.color["firewallT"] = color
	def setGoodFColor(self,color):
		self.color["good"] = color
	def setBadFColor(self,color):
		self.color["bad"] = color
	def clear(self):
		self.g =  gdot('G')
		self.g.attr(nodesep="0.25")
		self.g.attr(ordering="out")
		self.clearFW()
		self.clearFlows()
	def clearFW(self):
		self.firewall = set()
		self.firewallT = {}
		self.firewallAll = set()
	def clearFWT(self):
		self.firewallT = {}
	def clearFWF(self):
		self.firewall = set()
	def clearFWA(self):
		self.firewallAll = set()
	def clearFlows(self):
		self.edges = {}
	def FWAllNB(self):
		return len(self.firewallAll)
	def FWTNB(self):
		return len(self.firewallT)
	def FWFNB(self):
		return len(self.firewall)
	def addGoodPaths(self,g):
		for p in g:
			self.addGoodPath(p)
	def addBadPaths(self,b):
		for p in b:
			self.addBadPath(p)
	def addGoodPath(self,g):
		for i,j in pairwise(g):
			self.edges[(i,j)] = 1
	def addBadPath(self,b):
		for i,j in pairwise(b):
			self.edges[(i,j)] = 2
	def addGoodEdges(self,g):
		for t in g:
			if t in self.edges and self.edges[t] == 2:
				self.edges[t] = 0
			else:
				self.edges[t] = 1
	def addBadEdges(self,g):
		for t in g:
			if t in self.edges and self.edges[t] == 1:
				self.edges[t] = 0
			else:
				self.edges[t] = 2
	def addFlows(self,pv,bv={}):
		(ge,be) = edgesFromFlows(pv,self.net.G,self.net.B,self.traffics)
		self.addGoodEdges(ge) 
		self.addBadEdges(be) 
		if bv != {}:
			self.addBlocked(pv,bv)
		
	def addBlocked(self,pv,bv):
		self.blocked = {}
		flows2edges = {}
		for f in pv:
			i = f[1]
			j = f[2]
			if f[0] not in flows2edges :
				flows2edges[f[0]] = []
			flows2edges[f[0]].append((i,j))
		for f in bv:
			for (i,j) in flows2edges[f[0]]:
				self.blocked[(i,j)] = 1
			# i=f[1]
			# j=f[2]
			# self.blocked[(i,j)] = 1
	def setDebug(self,bool):
		self.debug = bool
	def addFirewall(self,node):
		self.firewall.append(node)
	def addAfffected(self,node):
		self.affected.append(node)
	def addFirewalls(self,nodes, drop=DROP.ALL):
		if(drop == DROP.ALL):
			self.firewallAll.update(nodes)
		elif (drop == DROP.TRAFFIC) :
			# print "nodes :" + str(nodes)
			for node in nodes : 
				key = node[1]
				value = node[0]
				if(not key in self.firewallT):
					self.firewallT[key] = set()
				self.firewallT[key].add(value)
		else:
			self.firewall.update(nodes)
	def addAffecteds(self,nodes):
		self.affected += nodes
	def setFirewallColor(self,color):
		self.color["firewall"] = color
	def setAffectedColor(self,color):
		self.color["affected"] = color
	def view(self,name="test2"):
		self.g =  gdot('G')
		self.g.attr(nodesep="0.25")
		self.g.attr(ordering="out")
		layers = []
		keys = self.net.topology.keys()
		keys.sort()
		for key in keys:
			layers.append(self.net.topology[key]) 
		self.buildDotGraphLayers(layers)
		self.g.render(NetworkViewer.directory+name,format='svg', view=True)

	def run(self,name="test2"):
		self.g =  gdot('G')
		self.g.attr(nodesep="0.25")
		self.g.attr(ordering="out")
		layers = []
		keys = self.net.topology.keys()
		keys.sort()
		for key in keys:
			layers.append(self.net.topology[key]) 
		self.buildDotGraphLayers(layers)
		# self.imagefile=self.g.pipe().decode('utf-8')
		self.imagefile = os.path.abspath(self.g.render(NetworkViewer.directory+name,format='jpeg', view=False))

	def buildDotGraphLayers(self,clusters):
		done=[]

		for cluster in clusters:
			for i in cluster:
				self.createNode(self.g,i),self.g.edge('0', str(i), style = 'invis')
		
			for i in range(len(cluster) -1):
				self.g.edge(str(cluster[i]),str(cluster[i+1]),style='invis')
				
		
		for cluster in clusters:
			with self.g.subgraph() as s:
				s.attr(rank='same')
				for i in cluster:
					s.node('%d' % i)
					
			for src in cluster:
				if src in self.net.asrc + self.net.asink:
					continue
				for adj in self.net.Graph.pred(src):
					if not(adj in self.net.asrc + self.net.asink):
						self.createEdge(src,adj,bidir=(src in self.net.Graph.succ(adj)),done=done)
						
						
		if self.debug or self.edges == {}:     
			for adj in self.net.asink:
				for src in self.net.Graph.pred(adj):
					self.createEdge(src,adj), self.g.edge("3",str(self.net.asink[0]), style = 'invis')
			for src in self.net.asrc:
				for adj in self.net.Graph.succ(src):
					self.createEdge(src,adj), self.g.edge(str(self.net.asrc[0]), "0", style = 'invis')


	def createNode(self,c,node):
		s="circle"
		if(node in self.net.H):
			s = self.shape["host"]
		elif(node in self.net.R):
			s = self.shape["routers"]
		if(node in self.firewall):
			c.node(str(node),color=self.color["firewall"],style='filled',shape=s)
		elif(node in self.firewallT):
			c.node(str(node),color=self.color["firewallT"],style='filled',shape=s,fontsize="6",label=""+str(node)+"\nT:"+str(list(self.firewallT[node])))
		elif(node in self.firewallAll):
			c.node(str(node),color=self.color["firewallAll"],style='filled',shape=s)
		elif( node in self.affected):
			c.node(str(node),color=self.color["affected"],style='filled',shape=s)
		elif(node in self.net.asink):
			c.node(str(node),color=self.color["sink"],style='filled',shape=self.shape["sink"],width="0.002",fontsize="5")
		elif(node in self.net.asrc):
			c.node(str(node),color=self.color["source"],style='filled',shape=self.shape["source"],width="0.02",fontsize="5")
		else:
			c.node(str(node),shape=s)

	def createEdge(self,i,j,bidir=False,done=[]):
		ts = self.traffics[(i,j)] if (i,j) in self.traffics else None
		if (i,j) in self.edges:
			if (i,j) in self.blocked:
				col = ''
				if(len(ts)) > 2:
					for t in ts:
						col+":"
				for t in ts :
					self.g.edge(str(i),str(j),color=self.color["traffics"][t],style = "dashed")
			elif self.edges[(i,j)] == 1:
				for t in ts :
					self.g.edge(str(i),str(j),color=self.color["traffics"][t])
			elif  self.edges[(i,j)] == 2:
				self.g.edge(str(i),str(j),color=self.color["bad"])
			else :
				self.g.edge(str(i),str(j),color=self.color["bad"]+":"+self.color["good"])
		else:
			if (i,j) in self.blocked:
				self.g.edge(str(i),str(j),color=self.color["blocked"],style = "dashed")
			elif not((i,j) in done or (j,i) in done or ((j,i) in self.edges and (i,j) in done)) :
				if(bidir and not (j,i) in self.edges):
					self.g.edge(str(i),str(j),dir="both",style = "invis") 
				else :
					self.g.edge(str(i),str(j),style = "invis") 
		done.append((i,j))

	def printDotSource(self):
		print(self.g.source)