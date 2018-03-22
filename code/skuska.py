import networkx as nx
#import matplotlib.pyplot as plt
from ryu.topology.api import get_switch, get_link
import random
from itertools import islice

def k_shortest_paths(pici, source, target, k):
	return list(islice(nx.shortest_simple_paths(pici,source,target),k))


net = nx.DiGraph()
nodes = [1,2,3,'A','B', 'C', 'D']
net.add_nodes_from(nodes)


edges = [[1,'A'],[2,'B'],[6,'C'],[8,'D'],['A',1],['B',2],['C',6],['D',8],[1,2],[2,1],[1,3],[3,1],[3,5],[5,3],[1,4],[4,1],[4,6],[6,4],[5,6],[6,5],[6,8],[8,6],[2,7],[7,2],[7,8],[8,7]]

net.add_edges_from(edges)



cesty = list(nx.all_simple_paths(net,'B','C'))

print cesty




#print type(cesty)

nova = []
for c in cesty:
	x = random.randint(1,100)
	tupla = (x,c)
	nova.append(tupla)
	#print type(c)
	#print c

print nova

nova = sorted(nova,key= lambda x: (len(x[1]), x[0]))

print nova[0][1]



