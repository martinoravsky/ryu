import networkx as nx
#import matplotlib.pyplot as plt
from ryu.topology.api import get_switch, get_link
import random
from itertools import islice

net = nx.DiGraph()
nodes = [1,2,3,4,5,6,7,8,9,10,11,'A','B','C','D']
net.add_nodes_from(nodes)

edges = [[1,2],[2,5],[1,3],[3,4],[4,5],[3,7],[7,8],[4,8],[6,7],[8,9],[6,9],[6,10],[10,9],[9,11],['A',1],['B',6],[5,'C'],[11,'D']]
edges2 = [[2,1],[5,2],[3,1],[4,3],[5,4],[7,3],[8,7],[8,4],[7,6],[9,8],[9,6],[10,6],[9,10],[11,9],[1,'A'],[6,'B'],['C',5],['D',11]]


net.add_edges_from(edges)
net.add_edges_from(edges2)

print net.nodes
print net.edges

import copy
path1 = nx.shortest_path(net,'A','C')
path_edges = zip(path1,path1[1:])
path2 = nx.all_simple_paths(net,'B','D')

print path_edges

for p in path2:
	cesta = p

path2_edges = zip(cesta,cesta[1:])




print set(path_edges)
print set(path2_edges)

if set(path_edges).isdisjoint(path2_edges):#
	print "Su disjoint"