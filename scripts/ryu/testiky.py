import networkx as nx
#import matplotlib.pyplot as plt
from ryu.topology.api import get_switch, get_link
import random
from itertools import islice

disjoints = []

disjoints.append({'path':'jozko','disjoints':1})
disjoints.append({'path':'ferko','disjoints':3})
disjoints.append({'path':'mirko','disjoints':2})


from operator import itemgetter
result = sorted(disjoints, key=itemgetter('disjoints'))[-1]['path']

print result
