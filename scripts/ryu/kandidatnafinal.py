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
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import tcp, ipv4
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
import networkx as nx
import binascii, hashlib, hmac, os, mysql.connector
from mysql.connector import Error
import random
from collections import defaultdict
from random import randrange
from ryu.app.ofctl.api import get_datapath
import sys
from ryu.lib.packet import arp
from ryu.lib import mac
from connection import connect
import copy


class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.mac_to_port = {}
		self.topology_api_app = self
		self.net = nx.DiGraph()
		self.nodes = {}
		self.links = {}
		self.table = {}
		self.cesty = []

	def executeInsert(self, query):
		"""
		Connect to MySQL database and execute INSERT
		"""
		try:
			conn = connect()
			if conn.is_connected():
				print('Connected do MySQL. Query: %s', query)
				cursor = conn.cursor()
				cursor.execute(query)
		except Error as e:
			print(e)
		finally:
			conn.commit()
			conn.close()

	def executeSelect(self, query):
		"""
		Connect to MySQL Database and execute SELECT
		"""
		try:
			conn = connect()
			if conn.is_connected():
				print('Connected do MySQL. Query: %s', query)
				cursor = conn.cursor()
				cursor.execute(query)
				result = cursor.fetchone()
				return result
		except Error as e:
			print(e)
		finally:
			conn.commit()
			conn.close()

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

		match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_flags=0x002)
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 2, match, actions)

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

	def del_flow(self, datapath, match):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
								out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
								match=match)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
							  ev.msg.msg_len, ev.msg.total_len)

		got = 0



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

		arp_pkt = pkt.get_protocol(arp.arp)

		if dst == mac.BROADCAST_STR:
			arp_dst_ip = arp_pkt.dst_ip
			arp_src_ip = arp_pkt.src_ip

			if (dpid, arp_src_ip, arp_dst_ip) in self.table:
				if self.table[(dpid, arp_src_ip, arp_dst_ip)] != in_port:
					datapath.send_packet_out(in_port=in_port, actions=[])
					return True
			else:
				self.table[(dpid, arp_src_ip, arp_dst_ip)] = in_port
				self.mac_to_port[datapath.id][src] = in_port

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			return

		#self.logger.info("prisiel paket na switch c. %d, src: %s, dst: %s, in_port: %s", dpid, src, dst, in_port)

		t = pkt.get_protocol(ipv4.ipv4)

		if t:
			print 'Zdrojova ip: ', t.src
			print 'Dest ip: ', t.dst

		ht = pkt.get_protocol(tcp.tcp)

		# If TCP
		if ht:
			#print 'zdrojovy port: ', ht.src_port
			#print 'destination port: ', ht.dst_port
			options = ht.option
			# Parse TCP options
			if options and len(options) > 0:
				for opt in options:
					# Parse MPTCP options
					if opt.kind == 30:
						# Parse MPTCP subtype. 00 = MP_CAPABLE. 01 = MP_JOIN. 11 = MP_JOIN
						hexopt = binascii.hexlify(opt.value)
						subtype = hexopt[:2]
						# MP CAPABLE
						if subtype == "00":
							# MP CAPABLE SYN
							if ht.bits == 2:
								self.logger.info("MP_CAPABLE SYN")

								# Vytvorim pravidlo pre SYN-ACK na opacnom smere
								match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.dst, ipv4_dst=t.src,
														tcp_flags=0x012)
								actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
								self.add_flow(datapath, 2, match, actions)

							# MP_CAPABLE SYN-ACK
							elif ht.bits == 18:
								self.logger.info("MP_CAPABLE SYN-ACK")

								# Vytvorim pravidlo pre ACK v opacnom smere
								match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.dst, ipv4_dst=t.src,
														tcp_flags=0x010)
								actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
								self.add_flow(datapath, 2, match, actions)

								# Zmazem pravidlo pre SYN-ACK v tomto smere
								match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.src, ipv4_dst=t.dst,
														tcp_flags=0x012)
								self.del_flow(datapath, match)

							# MP_CAPABLE ACK
							elif ht.bits == 16:
								self.logger.info("MP_CAPABLE ACK")

								# Zmazem pravidlo pre ACK v tomto smere
								match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.src, ipv4_dst=t.dst,
														tcp_flags=0x010)
								self.del_flow(datapath, match)

								tmp = list(nx.all_simple_paths(self.net, src, dst))

								print "vsetky mozne cesty:"
								for p in tmp:
									print p
								tmp = sorted(tmp, key=len)

								for c in tmp:
									if c not in self.cesty:
										self.cesty.append(c)

								print "ulozene cesty connectionu"
								print self.cesty

								path = self.cesty[0]

								got = 1
								fullpath = path
								tmppath = path[1:-1]
								for s in tmppath:
									match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.src, ipv4_dst=t.dst,
															tcp_src=ht.src_port, tcp_dst=ht.dst_port)
									next = fullpath[fullpath.index(s) + 1]
									out_port = self.net[s][next]['port']
									actions = [parser.OFPActionOutput(out_port)]
									self.logger.info("Instalujem out_port %d pravidlo do switchu %d", out_port, s)
									self.add_flow(get_datapath(self, s), 3, match, actions)

									match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.dst, ipv4_dst=t.src,
															tcp_src=ht.dst_port, tcp_dst=ht.src_port)
									prev = fullpath[fullpath.index(s) - 1]
									out_port = self.net[s][prev]['port']
									actions = [parser.OFPActionOutput(out_port)]
									self.logger.info("Instalujem out_port %d pravidlo do switchu %d", out_port, s)
									self.add_flow(get_datapath(self, s), 3, match, actions)

						# MP_JOIN
						elif subtype == "10" or subtype == "11":
							# MP_JOIN SYN
							if ht.bits == 2:
								self.logger.info("MP_JOIN SYN")

								# Send B->A traffic to controller
								match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.dst, ipv4_dst=t.src,
														tcp_flags=0x012)
								actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
								self.add_flow(datapath, 2, match, actions)

							# MP_JOIN SYN-ACK
							elif ht.bits == 18:
								self.logger.info("MP_JOIN SYN-ACK.")

								# Send A->B traffic to controller
								match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.dst, ipv4_dst=t.src,
														tcp_flags=0x010)
								actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
								self.add_flow(datapath, 2, match, actions)

								match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.src, ipv4_dst=t.dst,
														tcp_flags=0x012)
								self.del_flow(datapath, match)

							# MP_JOIN ACK
							elif ht.bits == 16:
								self.logger.info("MP_JOIN ACK.")

								cesta = []
								cesty_connectionu = []

								match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.src, ipv4_dst=t.dst,
														tcp_flags=0x010)
								self.del_flow(datapath, match)

								print self.cesty

								for c in self.cesty:
									if c[0] == '08:00:27:5f:ab:7f' and c[len(c)-1] == '08:00:27:72:ae:ed':
										cesty_connectionu.append(c)

								print "Cesty connectionu: "
								print cesty_connectionu

								print "Upravena cesta:"

								cesta = copy.deepcopy(random.choice(cesty_connectionu))
								cesta[0] = src
								cesta[len(cesta)-1] = dst

								print cesta

								fullpath = cesta
								tmppath = cesta[1:-1]
								for s in tmppath:
									match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.src, ipv4_dst=t.dst,
															tcp_src=ht.src_port, tcp_dst=ht.dst_port)
									next = fullpath[fullpath.index(s) + 1]
									out_port = self.net[s][next]['port']
									actions = [parser.OFPActionOutput(out_port)]
									self.logger.info("Instalujem out_port %d pravidlo do switchu %d", out_port, s)
									self.add_flow(get_datapath(self, s), 3, match, actions)

									match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.dst, ipv4_dst=t.src,
															tcp_src=ht.dst_port, tcp_dst=ht.src_port)
									prev = fullpath[fullpath.index(s) - 1]
									out_port = self.net[s][prev]['port']
									actions = [parser.OFPActionOutput(out_port)]
									self.logger.info("Instalujem out_port %d pravidlo do switchu %d", out_port, s)
									self.add_flow(get_datapath(self, s), 3, match, actions)

		if src not in self.net:
			self.net.add_node(src)
			self.net.add_edge(dpid, src, port=in_port)
			self.net.add_edge(src, dpid)

		#if dst in self.net:
		#	path = nx.shortest_path(self.net, src, dst)
		#	out_port = self.net[dpid][path[path.index(dpid) + 1]]['port']
		#else:
		#	print ("takuto DST nemam, musim floodovat")
		#	out_port = ofproto.OFPP_FLOOD

		self.mac_to_port[dpid][src] = in_port

		if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]
		else:
			out_port = ofproto.OFPP_FLOOD

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

		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions,
								  data=data)
		datapath.send_msg(out)

	@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev):
		switch_list = get_switch(self.topology_api_app, None)
		switches = [switch.dp.id for switch in switch_list]
		self.net.add_nodes_from(switches)

		links_list = get_link(self.topology_api_app, None)
		links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]

		for link in links_list:
			print link.src.port_no

		self.net.add_edges_from(links)
		links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)

		print ("******** List of links")
		print(self.net.edges())
