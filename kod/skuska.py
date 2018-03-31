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

def aredisjoint(path1, path2, m, n):
	tmp1 = copy.deepcopy(path1)
	tmp2 = copy.deepcopy(path2)
	tmp1.sort()
	tmp2.sort()
	i = 0
	j = 0
	while i < m and j < n:
		if tmp1[i] < tmp2[j]:
			i += 1
		elif tmp1[j] < tmp2[i]:
			j += 1
		else:  # if set1[i] == set2[j]
			return False
	return True


path1 = nx.shortest_path(net,'A','C')
print path1



paths2 = nx.all_simple_paths(net,'B','D')



for path2 in paths2:
	m = len(path1)
	n = len(path2)
	if aredisjoint(path1,path2,m,n):
		print "yes"
	else:
		print "no"
	print path1
	print path2




