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
net.add_edges_from([['A', 2, {'port': 1}], [2, 3, {'port': 2}]])

[1,2],[2,3]
print net

nodes = []

i=1

for node in net.nodes:
	nodes.append({'id':i, 'label':str(node),'meno':'ferko'+str(i)})
	i = i + 1

print nx.get_edge_attributes(net,'port')