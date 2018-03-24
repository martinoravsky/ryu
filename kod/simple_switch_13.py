# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types
from ryu.topology.api import get_switch, get_link
from ryu.app.ofctl.api import get_datapath
from ryu.topology import event, switches
import networkx as nx
from ryu.lib.packet import arp
from ryu.lib import mac



class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.mac_to_port = {}
		self.topology_api_app = self
		self.net = nx.DiGraph()
		self.nodes = {}
		self.links = {}
		self.novy = nx.DiGraph()
		self.ARPnet = nx.DiGraph()

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
											 actions)]
		if buffer_id:
			mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
									priority=priority, match=match,
									instructions=inst)
		else:
			mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
									match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
							  ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		dst = eth.dst
		src = eth.src
		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})


		arp_packet = pkt.get_protocol(arp.arp)

		if arp_packet and dst == mac.BROADCAST_STR:
			print ('***** ARP REQUEST *****')
			for linka in self.net.edges.data():
				print ('*** Spracujem linku: ',linka)
				match = parser.OFPMatch(eth_type=0x0806, eth_dst=mac.BROADCAST_STR)
				print ('*** Robim match na zaklade eth_dst: ', dst)
				out_port = linka[2]['port']
				print ('*** Posli von tymto portom: ', out_port)
				actions = [parser.OFPActionOutput(out_port)]
				self.add_flow(get_datapath(self,linka[0]),2,match,actions)
			return

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			return

		self.logger.info("prisiel paket na switch c. %d, src: %s, dst: %s, in_port: %s", dpid, src, dst, in_port)

		if src not in self.net:
			self.net.add_node(src)
			self.net.add_edge(dpid,src,port = msg.match['in_port'])
			self.net.add_edge(src,dpid)
			print ("nepoznam v sieti..: ",src)
			print ("pridavam do siete nasledovne nody:", src)
			print ("pridavam do siete nasledovne linky:")
			print(dpid, src, in_port)
			print(src,dpid)

		if dst in self.net:
			print ("takuto DST maaam")
			print ("takuto cestu som vymyslel zo %s do %s ", src,dst)
			path = nx.shortest_path(self.net,src,dst)
			# TODO
			if dpid not in path:
				return

			for p in path:
				print (p)
			print("aktualne potrebujem vediet na ktorom mieste v ceste sa nachadza moj switch")

			print("aktualny switch sa nachadza v ceste na %d mieste",path.index(dpid))
			print("potrebujem vediet co nasleduje za aktualnym switchom..",path[path.index(dpid)+1])

			following=path[path.index(dpid)+1]
			print("next je takyto: ", following)
			print("potrebujem vediet ktorym portom to mam poslat von:")
			print("je to tento port: ",self.net[dpid][following]['port'])
			out_port = self.net[dpid][path[path.index(dpid)+1]]['port']

			#print ("Som na switchi ",dpid,", dst je ",dst,", src je ",src," , out_port je ", out_port)
			# fullpath = path
			# tmppath = path[1:-1]
			# for s in tmppath:
			# 	print ("Riesim switch c. ",s)
			# 	print ("Eth_dst je:",dst)
			#
			# 	match = parser.OFPMatch(eth_dst=dst)
			# 	following = fullpath[fullpath.index(s) + 1]
			# 	print ("Nasledujuci switch je: ",following)
			#
			# 	out_port = self.net[s][following]['port']
			# 	print ("out_port z %d do %d je: ",s,following, out_port)
			# 	actions = [parser.OFPActionOutput(out_port)]
			# 	self.logger.info("Instalujem out_port %d pravidlo do switchu %d", out_port, s)
			# 	self.add_flow(get_datapath(self, s), 3, match, actions)
			#
			#
			# 	prev = fullpath[fullpath.index(s) - 1]
			# 	print ("Predosly switch je: ", prev)
			#
			# 	out_port = self.net[s][prev]['port']
			# 	print ("Out port z %d do %d je: ",s,prev,out_port)
			# 	match = parser.OFPMatch(eth_dst=src)
			# 	actions = [parser.OFPActionOutput(out_port)]
			# 	self.logger.info("Instalujem out_port %d pravidlo do switchu %d", out_port, s)
			# 	self.add_flow(get_datapath(self, s), 3, match, actions)
		else:
			print ("takuto DST nemam, musim floodovat")
			out_port = ofproto.OFPP_FLOOD

		# # learn a mac address to avoid FLOOD next time.
		# self.mac_to_port[dpid][src] = in_port
		#
		# if dst in self.mac_to_port[dpid]:
		# 	out_port = self.mac_to_port[dpid][dst]
		# else:
		# 	out_port = ofproto.OFPP_FLOOD

		actions = [parser.OFPActionOutput(out_port)]
		#
		# install a flow to avoid packet_in next time
		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
			if msg.buffer_id != ofproto.OFP_NO_BUFFER:
				self.add_flow(datapath, 1, match, actions, msg.buffer_id)
				return
			else:
				self.add_flow(datapath, 1, match, actions)
		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data

		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
								  in_port=in_port, actions=actions, data=data)
		datapath.send_msg(out)

		print ("***** Na konci eventin")
		print(self.net.edges.data())


	def remove_loops(self):
		print("********Rekalkulujem.")
		T = nx.minimum_spanning_tree(self.net.to_undirected())

		self.novy.add_edges_from(
			[(i, o, w) for i, o, w in self.net.edges(data=True) if ((i, o) in T.edges() or (o, i) in T.edges())])

		self.ARPnet = self.novy.copy()

		print("********Zmenseny graf: ")
		print self.net.edges.data()
	@set_ev_cls(event.EventSwitchEnter)

	def get_topology_data(self,ev):
		switch_list = get_switch(self.topology_api_app, None)
		switches = [switch.dp.id for switch in switch_list]
		self.net.add_nodes_from(switches)

		links_list = get_link(self.topology_api_app, None)
		links = [(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]

		for link in links_list:
			print link.src.port_no

		self.net.add_edges_from(links)
		links = [(link.dst.dpid,link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)

		print ("******** List of links")
		print(self.net.edges())

		self.remove_loops()

