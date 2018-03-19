import networkx as nx
import matplotlib.pyplot as plt

net = nx.DiGraph()
nodes = [1,2,3]
net.add_nodes_from(nodes)

net.add_edge(1,2,port=1)
net.add_edge(2,1,port=1)
net.add_edge(1,3,port=2)
net.add_edge(3,1,port=1)
net.add_edge(2,3,port=2)
net.add_edge(3,2,port=2)

T = nx.minimum_spanning_tree(net.to_undirected())
print(net.edges.data())

print([(i,o,w) for i,o,w in net.edges(data=True) if ((i,o) in T.edges() or (o,i) in T.edges())])

