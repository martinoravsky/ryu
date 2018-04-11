import networkx as nx
#import matplotlib.pyplot as plt
from ryu.topology.api import get_switch, get_link
import random
from itertools import islice

disjoints = []

disjoints.append({'path':'jozko','disjoints':1})
disjoints.append({'path':'ferko','disjoints':2})
disjoints.append({'path':'mirko','disjoints':3})

print disjoints

