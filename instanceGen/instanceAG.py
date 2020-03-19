#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

example terminal input to run:$
$ python instanceAG.py -o ft6 -p 6 -t 3
creates a 6 pod fattree with 54 hosts, 45 switches, file named ft6.json

@author: devoncallahan

This file generates clos-style fattrees in dot notation according to the
paper: "A Scalable Commodity Data Center Network Architecture" by Al-Fares,
Loukissas and Vahdat. Generates a detailed toplology with relevant characteristics.
Generates traffic demand.
"""
import math, argparse, json, random, pprint
import networkx as nx
from matplotlib import pyplot as plt
from collections import Counter 
import pprint
import exploitGen


def mk_topo(is_directed,pods,edge_cap,switch_cap,hpe):
    gw_cap=1000
    hosts_per_edge = int(math.floor ( pods / 2 ))
    num_hosts = int(math.floor((pods * pods * pods) /4 ))
    num_agg_switches = int(math.floor(pods * pods))
    num_core_switches = int(math.floor((pods * pods)/4))
    num_core_switches += 1

#0==default fat-tree host fan out, 1-n specified fan out    
    if hpe == 0:
        hosts_per_edge= int(math.floor ( pods / 2 ))
        num_hosts = int(math.floor((pods * pods * pods) /4 ))
    else:       
        hosts_per_edge=int(hpe)
        num_hosts = int(math.floor(num_agg_switches/2 * hosts_per_edge))
           
    core_switches = [(str(i), {"type":"core","color":"lime","capacity":switch_cap})
                       for i in range(1, num_core_switches )]

#agg_switches hold the aggregate and the edge switches
    agg_switches = [(str(i), {"type":"switch","color":"lime","capacity":switch_cap})
                    for i in range(num_core_switches  , num_core_switches + num_agg_switches)]
    
    hosts = [(str(i), {"type":"host","color":"cyan","capacity":1})
             for i in range (num_core_switches  + num_agg_switches, num_core_switches  + num_agg_switches + num_hosts)]   
  
#check to see if we want a directed graph, if so convert to DiGraph and return
    if is_directed:
        g=nx.DiGraph()
    else:
        g = nx.Graph() 
    g.add_nodes_from(core_switches)
    g.add_nodes_from(agg_switches)
    g.add_nodes_from(hosts)  
    host_offset = 0
    for pod in range(pods):
        core_offset = 0
        for sw in range(int(pods/2)):
            switch = agg_switches[(pod*pods) + sw][0]
            # Connect to core switches
            for port in range(int(pods/2)):
                core_switch = core_switches[core_offset][0]
                g.add_edge(core_switch,switch,cost=1,capacity=edge_cap)
                core_offset += 1

            # Connect to aggregate switches in same pod lower switch is edge switch
            for port in range(int(math.floor(pods/2)),pods):
                
                lower_switch = agg_switches[(pod*pods) + port][0]
                g.nodes[lower_switch]["capacity"]=switch_cap
                g.add_edge(switch,lower_switch,cost=1,capacity=edge_cap)
               
        for sw in range(int(math.floor(pods/2)),pods):
            switch = agg_switches[(pod*pods) + sw][0]
            # Connect to hosts
            for port in range(0,hosts_per_edge ): # First k/2 pods connect to upper layer
                host = hosts[host_offset][0]
                g.add_edge(switch,host,cost=1,capacity=edge_cap)
                
                host_offset += 1 
    #add an gw node as external host for external traffic, give unbounded capacity.
    g.add_node(str(num_core_switches + num_agg_switches + num_hosts), type= "gw",color="gray")   
    gateways=[]
    for n in g.nodes():
        if(g.nodes[n]["type"]=='gw'):
            gateways.append(n)       
  
    for i in core_switches:
       for n in gateways:
           core=i[0]
           gw=n
           g.add_edge(gw,core,cost=1,capacity=gw_cap)           
    return g
   
def generate_demand(G,fph,traf_types,pods,pct_i,pct_gw,num_tr_types,bi_dir,intra,f_vals):     
    hosts=[]
    internal_nodes=[]
    external_nodes=[]
    demands=[]
    # number of outgoing connections for each host, destination is chosen randomly   
    for i in G.nodes():
        if(G.nodes[i]["type"]=='host'):
            hosts.append(i)
    num_hosts=len(hosts)
    #find intra-rack(same edge switch) hosts
    iph=find_intra_rack(G,hosts)
    #create lists for usage of not repeating source or destination    
    for i in hosts:        
        external_nodes.append(i)

#####Internal Traffic ######## 
    '''
    - intra=False if we are not modeling intra rack traffic     
    - use random to create pairs of internal nodes based on pct_i and number of internal_hosts
    - dont remove nodes from pool, allows for repeated demand pairs, random selection
    - dividing by 2 so I dont double the number of flows per host, since both s and d are hosts'''
    internal_flows=math.ceil(num_hosts *fph* pct_i)
    i_pairs=list()
    counter=internal_flows
    while(counter>0):
        found_pair=False
        while(found_pair == False):
            pick1=random.sample(hosts,1)
            pick1=pick1[0]
            pick2=random.sample(hosts,1)
            pick2=pick2[0]
            if(pick1 != pick2):
                if(intra):#check if we want to model intra rack communications
                    if(pick2 not in iph[pick1]):
                        found_pair=True
                else:found_pair=True
        i_pairs.append((pick1,pick2))
        if(bi_dir):
            i_pairs.append((pick2,pick1))
        counter=counter - 1     
            
########  Gateway Traffic ####### 
#generate a gate way host to act as source of all external traffic, highest numbered host
    gw_flows=int(math.ceil(num_hosts *fph* pct_gw))
    gw_pairs=[]   
    for i in G.nodes():
        if(G.nodes[i]["type"]=='gw'):
            gw=i

    for i in range(gw_flows):
        i_host=random.sample(external_nodes,1)
        gw_pairs.append((i_host[0], gw))
        if(bi_dir==1):
            gw_pairs.append((gw, i_host[0]))

    print( len(i_pairs),"Internal pairs ",len(gw_pairs), "Gateway pairs ")
    all_pairs = i_pairs + gw_pairs
    flows=[]
    flows.append(("internal flows", len(i_pairs)))
    flows.append(("gw flows", len(gw_pairs)))
    #reflect 10% large flows and 90% small flows as was found in research on DC traffic analysis
    for p in all_pairs:
        r=random.randrange(1,100)
        if (r < 90):  
            flow=random.randrange(1,10)
        if (r >=90):
            flow=random.randrange(100,1000)
       
        f={"o":p[0],"d":p[1],"f": flow,"s":traf_types[random.randrange(0,num_tr_types)],"v":random.choice(f_vals)}
        demands.append(f)   
    return demands,all_pairs, flows

def get_link_data(G,is_directed):
    links=[]
    for i in G.edges.items():
        l={"i":int(i[0][0]), "j":int(i[0][1]),"capacity":i[1]["capacity"], "cost":i[1]["cost"]}
        links.append(l)
        if is_directed :
            l={"i":int(i[0][1]), "j":int(i[0][0]),"capacity":i[1]["capacity"], "cost":i[1]["cost"]}
            links.append(l)
    return links

# not used, to bump edge capacity to meet demand.
def update_edge_capacity(G,all_pairs,max_demand):
    cups=[]
    for n in all_pairs:
        cups.append(n[0])
        cups.append(n[1])
    max_o=Counter(cups).most_common(1)[0][1]
    u_capacity = max_demand * max_o
    
    for i in G.edges.items():
        i[1]["capacity"]=u_capacity         
    return(G)        
        
def format_output(G,types,g_demands,links,mulA,percentInfectedH,nbEbyH,pl,sizeE,nbExploits):
    network={}
    graph={}
    graph["size"]=G.number_of_nodes()
    edges={}
    for n in G.nodes():
        edges[n] = list(map(int, G.adj[n]))
    graph["edges"]=edges
    hst=[]
    rtr=[]
    gw=[]
    for n in G.nodes():
        if(G.nodes[n]["type"]=='host'):
            hst.append(n)
        if(G.nodes[n]["type"]=='switch'):
            rtr.append(n)
        if(G.nodes[n]["type"]=='core'):
            rtr.append(n)
        if(G.nodes[n]["type"]=='gw'):
            hst.append(n)
            gw.append(n)
    gateways = [int(i) for i in gw] 
    network["graph"] = graph
    network["routers"] = [int(i) for i in rtr] 
    network["gateways"] = gateways
    network["hosts"]=[int(i) for i in hst]
    network["traffics"]=types
    network["good"]=g_demands
    network["cc"]=links
    network["memory"] = makeMemory(rtr + hst)
    network["compCost"] = makeAssets(gw,hst,mulA)
    network["permissionLevels"] = makePermissions(gw,hst,mulA,pl)
    network["switchCap"] = getCapacity(rtr)
    network["topology"] = makeTopology(G,rtr,hst)
    intrahost = set([])
    extrahost = set([])
    for f in g_demands:
        o = int(f['o'])
        d = int(f['d'])
        if o in gateways or d in gateways:
            other = o if d in gateways else d
            extrahost.add(other)
        else :
            intrahost.add(o)
            intrahost.add(d)
    maxPerm = len(mulA)-1
    exploits = exploitGen.generateRandomConnectedExploits(intrahost, extrahost, [int(i) for i in hst], percentInfectedH, nbExploits, maxPerm, len(types))
    # exploits = exploitGen.generateExploit(hst, percentInfectedH, nbEbyH,sizeE,len(mulA),len(types),network["permissionLevels"],single=False)
    network["exploits"] = exploits
    return(network)

def find_intra_rack(G,hosts):
    iph={}
    for i in hosts:
        iph[i]=[] 
        parent=set(G.neighbors(i))
        for j in parent:
            two_hops=set(G.neighbors(j))
            for k in two_hops:
                if k in hosts:
                    if i != k:
                        iph[i].append(k)                                                 
    return(iph)

def makeMemory(l):
    r = {}
    for i in l:
        r[i] = 100
    return r

def getCapacity(l):
    r = {}
    for i in l:
        r[i] = G.nodes[i]["capacity"]
    return r

#used in Attack Graph security module
def makePermissions(gw,hst,mulA,maxPl):
    p={}
    for i in gw:
        p[i]=1
    for i in hst:
        p[i]=len(mulA)
    return p

def makeAssets(gw,l,mulA):
    r = {}
    for i in gw:
        r[i]=[ 0 ]
    for i in l:
        av = random.randrange(1,100)
        cost=[]
        for j in mulA:
            cost.append(av*j)
        r[i] = cost 
    return r
              
def makeTopology(G,r,host):
    l = []
    p = host
 # ! problem G.predecessors(n), no pred in undirected graph   
    if nx.is_directed(G) == False:
        return None
    while len(p) > 0 :
        np = set()
        for n in p:
            preds = set(G.predecessors(n))
            np |= preds
        l.append(p)
        p = list(np)
    l.reverse() 
    return {i:list(map(int, l[i])) for i in range(0,len(l))}

def write_stats(G,file_name,good_demand,flows):     
    num_hosts=0
    for n in G.nodes():
        if(G.nodes[n]["type"]=='host'):
            num_hosts=num_hosts+1
    file1 = open("stats.txt","a")
 
    file1.write("************************** \n")
    file1.write(file_name)
    file1.write("\n")
    file1.write("network density ")
    file1.write(str(nx.density(G)))
    file1.write("\n")
    file1.write("number of nodes ")
    file1.write(str(len(G.nodes())))
    file1.write("\n")
    file1.write("number of edges ")
    file1.write(str( len(G.edges())))
    file1.write("\n")
    file1.write("number of hosts ")
    file1.write(str(num_hosts))
    file1.write("\n")
    num_switches= len(G.nodes())- num_hosts
    file1.write("number of switches ")
    file1.write(str(num_switches))
    file1.write("\n")
    file1.write("number of good flows ")
    file1.write(str(len(good_demand)))
    file1.write("\n")
    file1.write(str(flows))
    file1.write("\n")
    file1.close() 

def write_json(file_name, data):
    #write the network to a JSON file  read it in for testing
    s=json.dumps(data,indent=4, separators=(',', ': '))
    open(file_name+".json","w").write(s)

def draw_net(G, file_name): 
    colors=[]
    for i in G.nodes():
        colors.append(G.nodes[i]["color"])

    plt.figure(figsize=(12,12))
    ax = plt.subplot(111)
    ax.set_title('internal hosts are cyan, sdn devices are green, external hosts are gray', fontsize=10)
    nx.draw(G,pos=nx.kamada_kawai_layout(G),with_labels=True, node_color=colors)    
    plt.savefig(file_name + ".png", format="PNG") 
    
#can simply modify the default value for pods to increase the tree size using even increments
def parse_args():
    parser = argparse.ArgumentParser(description="""This file generates clos-style fattrees Data Center Network Architecture.
                                     Graph is non-directional. Allows, variable number of pods, number of hosts per edge switch,
                                     and nodes targeted in notional attack.
                                     usage: $ python ft_instance.py -o ft6 -p 6 -t 3""")
    parser.add_argument("-b","--bidirectional traffic",action="store",dest="bi_dir",
                        default=True,
                        help="0 for one way traffic, 1 to duplicate traffic pair in reverse")
    parser.add_argument("-g","--save graph file",type=bool,action="store",dest="print_graph",
                        default=False,
                        help="0 for one way traffic, 1 to duplicate traffic pair in reverse")                   
    parser.add_argument("-p","--pods",type=int,action="store",dest="pods",
                        default=4,
                        help="number of pods (parameter k in the paper)")
    parser.add_argument("-s","--seed",type=int,action="store",dest="seed",
                        default=6,
                        help="random seed")  
    parser.add_argument("-ws","--with-seed",action="store_true",dest="useSeed",
                        default=False,
                        help="random seed")  
    parser.add_argument("-ec","--edge-capacity",type=int, action="store",dest="edge_cap",
                        default=1000,
                        help="edge capacity")
    parser.add_argument("-sc","--switch-capacity",type=int, action="store",dest="switch_cap",
                        default=108000,
                        help="switch capacity")
    parser.add_argument("-hps","--hosts per edge switch",type=int, action="store",dest="hpe",
                        default=0,
                        help="enter 0 to use the default fat-tree of pod/2 or specify value for fan out per edge switch")
    parser.add_argument("-d","--directed graph",action="store_true",dest="directed",
                        default=False,
                        help="") 
    parser.add_argument("-o", "--out", action="store",dest="output",
                        default= "test",
                        help="file root to write to")
                                             
    parser.add_argument("-fph", "--flows per host",type=int, action="store",dest="fph",
                        default=1,
                        help="multiplier to get the size of a flow, packets size * fph= flow size") 
    parser.add_argument("-internal", "--percent internal", type=float,action="store",dest="pct_i",
                        default=.7,
                        help="percent of flows for internal to internal hosts")
    parser.add_argument("-gw", "--percent wan external",type=float, action="store",dest="pct_gw",
                        default=.3,
                        help="percent of flows from host to external sources")

    parser.add_argument("-ntt", "--number of traffic types",type=int, action="store",dest="num_tr_types",
                        default=2,
                        help="percent of flows from host to external sources")
    parser.add_argument("-irt", "--intra rack traffic",type=bool, action="store",dest="intra",
                        default=False,
                        help="Do we create intra rack track traffic?")
    parser.add_argument("-pi", "--percentInfected",type=int, action="store",dest="percentInfected",
                        default=0)
    parser.add_argument("-ebh", "--exploitsByHost",type=int, action="store",dest="exploitByHost",
                        default=3)
    parser.add_argument("-pl", "--permissionLevel",type=int, action="store",dest="permissionLevel",
                        default=3)
    parser.add_argument("-soe", "--sizeOfExploit",type=int, action="store",dest="sizeOfExploit",
                        default=2)
    parser.add_argument("-nbe", "--numberOfExploit",type=int, action="store",dest="nbExploits",
                        default=5)
    return parser.parse_args()
    
if __name__ == "__main__":
    args = parse_args()
    a_vals = [100,200,500]# each host is assigned a value from mulA
    f_vals=[1,2,3,5,25] # each flow is assigned a value from f_vals
    trafficType = [] #traffic is assigned a type 1 thru n
    for i in range(1,args.num_tr_types +1):
        trafficType.append(i)

    if args.useSeed :
        random.seed(args.seed)
    
    args.hpe = 2 if args.pods == 2 else args.hpe 
    # make the Fat-tree topo, assign edge and switch capacities
    G = mk_topo(args.directed,args.pods,args.edge_cap,args.switch_cap,args.hpe)
    # generate traffic demand, internal and external 
    demand,all_pairs,flows=generate_demand(G,args.fph,trafficType,args.pods,args.pct_i,args.pct_gw,args.num_tr_types, args.bi_dir,args.intra,f_vals)
    cc=get_link_data(G,args.directed)
    #calls generate exploits and formats out put data to json
    all_data=format_output(G,trafficType,demand,cc,a_vals,args.percentInfected,args.exploitByHost,args.permissionLevel,args.sizeOfExploit,args.nbExploits)
    #append instance info to stats file
    write_stats(G,args.output,demand,flows)
    write_json(args.output,all_data)

    if args.print_graph:
        draw_net(G,args.output)

    pp = pprint.PrettyPrinter()
    pp.pprint(all_data)
    pp.pprint(all_data["exploits"])