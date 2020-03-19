# FASHION
Functional and Attack graph Secured HybrId Optimization of virtualized Networks
Fashion's goal is to balance the functionality and security needs of the network.
Functionality needs are relatively straightforward to state: a set of desired network 
Flows that should be carried in the network while respecting link capacity.
Security is more complicated to state. We use the abstraction of attack graphs.

[FASHION Pipeline](pipeline.png)

## Optimization Model
Fashion considers both functionality and security when deciding how to configure the network. The functional layer treats network traffic as a multi-commodity data flow problem and provides the logic to route flows. To enable
the security layer, we introduce security metrics which can be evaluated using
linear programming to deliver quick calculation of risk on related networks. The
security layer then integrates the risk of a configuration to create a joint model
between the two layers. This joint model (solved with integer linear program-
ming) focuses on reconfiguring the network.

## Instance Generation
Generates a JSON file consisting of a Fat-tree network topology, traffic demand and network vulnerabilities. This file generates clos-style Fat-tree according to the paper: "A Scalable Commodity Data Center Network Architecture" by Al-Fares,Loukissas and Vahdat. Designed to be input for Optimization framework FASHION.

## Attack Graphs
[Attack Graph Example](attack_graph.png)

(Probabilistic) Attack graphs are used to model risk. An attack graph
is a labeled transition system that models an adversary's capabilities within a
network and how those can be elevated by transitioning to new states via the
exploitation of vulnerabilities (e.g., a weak password, a bug in a software package,
the ability to guess a stack address,...). In this work, we focus on risk that is due
to network configuration.


