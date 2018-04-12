import networkx as nx
import json
#import matplotlib.pyplot as plt
from ryu.topology.api import get_switch, get_link
import random
from itertools import islice


def getidfromedge(edge):
	for node in nodes:
		if edge == node['label']:
			return node['id']


net = nx.DiGraph()
vrcholy = [1,2,3,4,5,6,7,8,9,'A', 'B']
net.add_nodes_from(vrcholy)
net.add_edges_from([['A',2],[2,3]])

[1,2],[2,3]
print net

nodes = []

i=1

for node in net.nodes:
	nodes.append({'id':i, 'label':str(node)})
	i = i + 1

print nodes
edges = []


for edge in net.edges:
	od = getidfromedge(edge[0])
	to = getidfromedge(edge[1])
	edges.append({'from':od, 'to': to})


print edges
