import networkx as nx
#import matplotlib.pyplot as plt
from ryu.topology.api import get_switch, get_link
import random
from itertools import islice

mpcap = {}
mpcap['jozko'] ={"meno": "jozko", "priezvisko": "mrkvicka"}
mpcap['ferko'] = {"meno": "ferko", "priezvisko": "mrkvicka"}
mpcap['jozko']['vek'] = 17
mpcap['jozko']['cesty'] = [1]

mpcap['jozko']['cesty'].append([2])


mpcap['jozko']['salala'] = 'okjlkj'


for k,v in mpcap.iteritems():
	if v['priezvisko'] == 'mrkvicka':
		print k


