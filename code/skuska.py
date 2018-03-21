import networkx as nx
#import matplotlib.pyplot as plt
from ryu.topology.api import get_switch, get_link


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

nove = nx.DiGraph()
nove.add_edges_from([(i,o,w) for i,o,w in net.edges(data=True) if ((i,o) in T.edges() or (o,i) in T.edges())])

print nove.edges.data()

links_list = get_link(topology_api_app, None)
links = [(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		
for jozko in net.edges.data():
	if jozko in nove.edges.data():
		print ("switch je: ", jozko[0], ", port je ", jozko[2]['port'])