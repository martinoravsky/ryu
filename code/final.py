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

		arp_pkt = pkt.get_protocol(arp.arp)

		if dst == mac.BROADCAST_STR:
			arp_dst_ip = arp_pkt.dst_ip
			arp_src_ip = arp_pkt.src_ip

			if(dpid, arp_src_ip, arp_dst_ip) in self.table:
				if self.table[(dpid,arp_src_ip,arp_dst_ip)] != in_port:
					datapath.send_packet_out(in_port=in_port, actions=[])
					return True
			else:
				self.table[(dpid,arp_src_ip,arp_dst_ip)] = in_port
				print self.table
				self.mac_to_port[datapath.id][src] = in_port

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			return

		self.logger.info("prisiel paket na switch c. %d, src: %s, dst: %s, in_port: %s", dpid, src, dst, in_port)

		if src not in self.net:
			self.net.add_node(src)
			self.net.add_edge(dpid,src,port = msg.match['in_port'])
			self.net.add_edge(src,dpid)

		t = pkt.get_protocol(ipv4.ipv4)

		if t:
			print 'zdrojova ip: ', t.src
			print 'dest ip: ', t.dst

		ht = pkt.get_protocol(tcp.tcp)
		found_path = 0

		# If TCP
		if ht:
			print 'zdrojovy port: ', ht.src_port
			print 'destination port: ', ht.dst_port
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

								# Send A->B traffic to controller
								match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.src, ipv4_dst=t.dst,
														tcp_src=ht.src_port, tcp_dst=ht.dst_port)
								actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
																  ofproto.OFPCML_NO_BUFFER)]
								self.add_flow(datapath, 3, match, actions)

								# Send B->A traffic to controller
								match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.dst, ipv4_dst=t.src,
														tcp_src=ht.dst_port, tcp_dst=ht.src_port)
								actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
																  ofproto.OFPCML_NO_BUFFER)]
								self.add_flow(datapath, 3, match, actions)

								# Sender's key.
								keya = hexopt[4:]

								# Sender's token is a SHA1 truncated hash of the key.
								tokena = int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8], 16)

								# Store IPs, ports, sender's key and sender's token.
								values = {'tsrc': t.src, 'tdst': t.dst, 'keya': keya, 'tokena': tokena,
										  'htsrc_port': ht.src_port, 'htdst_port': ht.dst_port, 'src': src, 'dst': dst}
								query = "replace INTO mptcp.conn (ip_src,ip_dst,keya,tokena,tcp_src,tcp_dst,src,dst) values('{tsrc}','{tdst}','{keya}',{tokena},{htsrc_port},{htdst_port},'{src}','{dst}');"
								self.executeInsert(query.format(**values))
							# MP_CAPABLE SYN-ACK
							elif ht.bits == 18:
								self.logger.info("MP_CAPABLE SYN-ACK")

								# Receiver's key.
								keyb = hexopt[4:]

								# Receiver's token is a SHA1 truncated hash of the key.
								tokenb = int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8], 16)

								# Store receiver's key and receiver's token to the appropriate connection.
								values = {'tsrc': t.src, 'tdst': t.dst, 'htsrc_port': ht.src_port,
										  'htdst_port': ht.dst_port, 'keyb': keyb, 'tokenb': tokenb}
								query = "UPDATE mptcp.conn SET keyb='{keyb}',tokenb={tokenb} WHERE ip_src='{tdst}' AND ip_dst='{tsrc}' AND tcp_src={htdst_port} AND tcp_dst={htsrc_port};"
								self.executeInsert(query.format(**values))

							# MP_CAPABLE ACK
							elif ht.bits == 16:
								self.logger.info("MP_CAPABLE ACK")

								found_path = 1
								dpid = datapath.id
								paths = list(nx.all_shortest_paths(self.net, src, dst))
								#								macs = src+'-'+dst
								path = random.choice(paths)
								#								if macs in self.connpaths: #Ak uz mam zvolenu cestu
								#									self.logger.info("Pre takyto srcdst uz mam zvolenu cestu. Pouzijem tuto cestu:")
								#									path = paths[self.connpaths[macs]]
								#									print(path)
								#								else:
								#									self.logger.info("Pre takyto srcdst nemam este cestu. Pouzijem tuto cestu:")
								#									path_index = randrange(0,len(paths))
								#									path = paths[path_index]
								#									self.connpaths[macs] = path_index
								#									print(path)
								#									print(self.connpaths[macs])
								#									self.logger.info("Takyto je random index: %d.",path_index)

								# path=['08:00:27:5f:ab:7f', 1, 5, 6, '08:00:27:77:27:8c']
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
						#								command = 'ovs-ofctl -OOpenFlow13 del-flows s1 "eth_dst='+dst+',tcp,tcp_flags=0x010"'
						#								os.system(command)

						# MP_JOIN
						elif subtype == "10" or subtype == "11":
							# MP_JOIN SYN
							if ht.bits == 2:
								self.logger.info("MP_JOIN SYN")

								# Send A->B traffic to controller
								match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.src, ipv4_dst=t.dst,
														tcp_src=ht.src_port, tcp_dst=ht.dst_port)
								actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
																  ofproto.OFPCML_NO_BUFFER)]
								self.add_flow(datapath, 3, match, actions)

								# Send B->A traffic to controller
								match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=t.dst, ipv4_dst=t.src,
														tcp_src=ht.dst_port, tcp_dst=ht.src_port)
								actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
																  ofproto.OFPCML_NO_BUFFER)]
								self.add_flow(datapath, 3, match, actions)

								# Receiver's token. From the MPTCP connection.
								tokenb = int(hexopt[4:][:8], 16)

								# Sender's nonce.
								noncea = hexopt[12:]

								# Store IPs, ports, sender's nonce into subflow table.
								values = {'tsrc': t.src, 'tdst': t.dst, 'tokenb': tokenb, 'noncea': noncea,
										  'htsrc_port': ht.src_port, 'htdst_port': ht.dst_port}
								query = "replace INTO mptcp.subflow (ip_src,ip_dst,tokenb,noncea,tcp_src,tcp_dst) values('{tsrc}','{tdst}',{tokenb},'{noncea}',{htsrc_port},{htdst_port});"
								self.executeInsert(query.format(**values))

							# MP_JOIN SYN-ACK
							elif ht.bits == 18:
								self.logger.info("MP_JOIN SYN-ACK.")

								# Receiver's truncated HASH.
								trunhash = int(hexopt[4:][:16], 16)

								# Receiver's nonce.
								nonceb = hexopt[20:]

								# Store truncated HASH and receiver's nonce into appropriate subflow.
								values = {'tsrc': t.src, 'tdst': t.dst, 'htsrc_port': ht.src_port,
										  'htdst_port': ht.dst_port, 'trunhash': trunhash, 'nonceb': nonceb}
								query = "UPDATE mptcp.subflow SET trunhash={trunhash},nonceb='{nonceb}' WHERE ip_src='{tdst}' AND ip_dst='{tsrc}' AND tcp_src={htdst_port} AND tcp_dst={htsrc_port};"
								self.executeInsert(query.format(**values))

							# MP_JOIN ACK
							elif ht.bits == 16:
								self.logger.info("MP_JOIN ACK.")

								found_path = 1
								dpid = datapath.id
								paths = list(nx.all_shortest_paths(self.net, src, dst))
								#							macs = src+'-'+dst
								path = random.choice(paths)
								#							if macs in self.connpaths: #Ak uz mam zvolenu cestu
								#								self.logger.info("Pre takyto srcdst uz mam zvolenu cestu. Pouzijem tuto cestu:")
								#								path = paths[self.connpaths[macs]]
								#								print(path)
								#							else:
								#								self.logger.info("Pre takyto srcdst nemam este cestu. Pouzijem tuto cestu:")
								#								path_index = randrange(0,len(paths))
								#								path = paths[path_index]
								#								self.connpaths[macs] = path_index
								#								print(path)
								#								print(self.connpaths[macs])
								#								self.logger.info("Takyto je random index: %d.",path_index)

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

								# Sender's HASH.
								hmachash = hexopt[4:]

								# Store sender's HASH to appropriate subflow.
								values = {'tsrc': t.src, 'tdst': t.dst, 'htsrc_port': ht.src_port,
										  'htdst_port': ht.dst_port, 'hmachash': hmachash}
								query = "UPDATE mptcp.subflow SET hash='{hmachash}' WHERE ip_src='{tsrc}' AND ip_dst='{tdst}' AND tcp_src={htsrc_port} AND tcp_dst={htdst_port};"
								self.executeInsert(query.format(**values))

								# Select keys from appropriate connection based on receiver's token.
								values = {'tsrc': t.src, 'tdst': t.dst, 'htsrc_port': ht.src_port,
										  'htdst_port': ht.dst_port}
								query = "SELECT keya,keyb from conn where tokenb in (SELECT tokenb from subflow where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port});"
								keys = self.executeSelect(query.format(**values))

								# Select nonces for current subflow.
								values = {'tsrc': t.src, 'tdst': t.dst, 'htsrc_port': ht.src_port,
										  'htdst_port': ht.dst_port}
								query = "SELECT noncea,nonceb from subflow where ip_src='{tsrc}' AND ip_dst='{tdst}' AND tcp_src={htsrc_port} AND tcp_dst={htdst_port};"
								nonces = self.executeSelect(query.format(**values))

								# Key for generating HMAC is a concatenation of two keys. Message is a concatenation of two nonces.
								keyhmac = binascii.unhexlify(keys[0] + keys[1])
								message = binascii.unhexlify(nonces[0] + nonces[1])

								# Generate hash.
								vysledok = hmac.new(keyhmac, message, hashlib.sha1).hexdigest()
								print(vysledok)

								# Compare generated HASH to the one from MP_JOIN ACK.
								if vysledok == hmachash:
									# Get connection ID based on tokens.
									values = {'tsrc': t.src, 'tdst': t.dst, 'htsrc_port': ht.src_port,
											  'htdst_port': ht.dst_port}
									query = "SELECT id from conn where tokenb in (SELECT tokenb from subflow where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port});"
									ids = self.executeSelect(query.format(**values))[0]

									# Insert connection ID to a current subflow.
									values = {'tsrc': t.src, 'tdst': t.dst, 'htsrc_port': ht.src_port,
											  'htdst_port': ht.dst_port, 'id': ids}
									query = "update subflow set connid = {id} where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port};"
									self.executeInsert(query.format(**values))

									query = "select src,dst from conn join subflow on subflow.connid=conn.id where conn.id=(select connid from subflow where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port}) group by src;"

									result = self.executeSelect(query.format(**values))
									srcmac = result[0]
									dstmac = result[1]
									print ('srcmac = %s', srcmac)
									print ('dstmac = %s', dstmac)

		if dst in self.net:
			path = nx.shortest_path(self.net,src,dst)

			if dpid not in path:
				return

			out_port = self.net[dpid][path[path.index(dpid)+1]]['port']

		else:
			print ("takuto DST nemam, musim floodovat")
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

		out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
								  in_port=in_port, actions=actions, data=data)
		datapath.send_msg(out)

		print ("***** Na konci eventin")
		print(self.net.edges.data())


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



