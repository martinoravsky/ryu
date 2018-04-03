import binascii
import copy
import hashlib
import hmac
import networkx as nx
from ryu.app.ofctl.api import get_datapath
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.lib import mac
from ryu.lib.packet import packet, ethernet, ether_types, tcp, ipv4, arp
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link


class SimpleSwitch13(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		"""
		Initialize stuff.

		"""
		super(SimpleSwitch13, self).__init__(*args, **kwargs)
		self.mac_to_port = {}
		self.topology_api_app = self
		self.net = nx.DiGraph()
		self.nodes = {}
		self.links = {}
		self.table = {}
		self.cesty = []
		self.subflows = {}
		self.syn = []
		self.synack = []
		self.ack = []

	def are_node_disjoint(self,p,cesty):
		for cesta in cesty:
			tmp1 = copy.deepcopy(cesta)
			tmp2 = copy.deepcopy(p)
			tmp1 = tmp1[1:-1]
			tmp2 = tmp2[1:-1]

			if set(tmp1).isdisjoint(tmp2):
				#print "Path ", cesta, "is node-disjoint with", p
				return p
		return 0

	def are_edge_disjoint(self, p, cesty):
		for cesta in cesty:
			tmp1 = copy.deepcopy(cesta)
			tmp2 = copy.deepcopy(p)
			tmp1 = tmp1[1:-1]
			tmp2 = tmp2[1:-1]

			revedges1 = []
			revedges2 = []

			rev1 = copy.deepcopy(tmp1[::-1])
			rev2 = copy.deepcopy(tmp2[::-1])

			edges1 = zip(tmp1, tmp1[1:])
			edges2 = zip(tmp2, tmp2[1:])

			revedges1 = zip(rev1, rev1[1:])
			revedges2 = zip(rev2, rev2[1:])

			edges1 = edges1 + revedges1
			edges2 = edges2 + revedges2

			if set(edges1).isdisjoint(edges2):
				print "Path ", cesta, "is edge-disjoint with", p
				return p
		return 0

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		"""
		If nothing is matched on a switch, send that to a controller.
		Match TCP SYN packets.

		"""
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
		self.add_flow(datapath, 3, match, actions)

	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		"""
		Add a flow for specified match.

		"""
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
		"""
		Delete a flow for specified match.

		"""
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
								out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
								match=match)
		datapath.send_msg(mod)

	def break_broadcast_storm(self, pkt, src, dst, datapath, in_port):
		"""
		Maintain ARP table (dpid, source_ip, destination_ip)
		so when broadcast storm occurs, break the loop.
		"""
		dpid = datapath.id
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

	def mp_capable_syn(self, datapath, tcp_pkt, ip, src, dst, hexopt):
		identifier = ip.src + ip.dst + str(tcp_pkt.src_port) + str(tcp_pkt.dst_port)

		if identifier not in self.syn:
			print "MP_CAPABLE SYN"

			ofproto = datapath.ofproto
			parser = datapath.ofproto_parser

			paths = []

			self.syn.append(identifier)

			# Sender's token is a SHA1 truncated hash of the key.
			self.subflows[identifier] = {'tokena':
											int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8], 16),
											'ip_src': ip.src,
											'ip_dst': ip.dst,
											'tp_src': tcp_pkt.src_port,
											'tp_dst': tcp_pkt.dst_port,
											'keya': hexopt[4:],
											'main': True,
										 	'paths': paths}

			# Vytvorim pravidlo pre SYN-ACK na opacnom smere
			match = parser.OFPMatch(eth_type=0x0800,
									ip_proto=6,
									ipv4_src=ip.dst,
									ipv4_dst=ip.src,
									tcp_src=tcp_pkt.dst_port,
									tcp_dst=tcp_pkt.src_port,
									tcp_flags=0x012)
			actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
			self.add_flow(datapath, 2, match, actions)

	def mp_capable_syn_ack(self, datapath, tcp_pkt, ip, src, dst, hexopt):
		identifier = ip.dst + ip.src + str(tcp_pkt.dst_port) + str(tcp_pkt.src_port)

		if identifier not in self.synack:
			print "MP_CAPABLE SYN-ACK"

			self.synack.append(identifier)

			self.subflows[identifier]['tokenb'] = int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8], 16)
			self.subflows[identifier]['keyb'] = hexopt[4:]

			# Vytvorim pravidlo pre ACK v opacnom smere
			ofproto = datapath.ofproto
			parser = datapath.ofproto_parser
			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.dst, ipv4_dst=ip.src,
									tcp_src=tcp_pkt.dst_port,tcp_dst=tcp_pkt.src_port,
									tcp_flags=0x010)

			actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
			self.add_flow(datapath, 2, match, actions)

			# Zmazem pravidlo pre SYN-ACK v tomto smere
			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.src, ipv4_dst=ip.dst,
									tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port,
									tcp_flags=0x012)
			self.del_flow(datapath, match)

	def mp_capable_ack(self, datapath, tcp_pkt, ip, src, dst, hexopt):
		identifier = ip.src+ip.dst+str(tcp_pkt.src_port)+str(tcp_pkt.dst_port)

		if identifier not in self.ack:
			print "MP_CAPABLE ACK."

			self.ack.append(identifier)

			parser = datapath.ofproto_parser

			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.src, ipv4_dst=ip.dst,
									tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port,
									tcp_flags=0x010)
			self.del_flow(datapath, match)

			tmp = nx.shortest_path(self.net, src, dst)

			self.subflows[identifier]['paths'] = tmp

			self.install_path(datapath, tcp_pkt, ip, tmp)

	def mp_join_syn(self, datapath, tcp_pkt, ip, hexopt):

		identifier = ip.src+ip.dst+str(tcp_pkt.src_port)+str(tcp_pkt.dst_port)

		if identifier not in self.syn:
			print "MP_JOIN SYN"
			parser = datapath.ofproto_parser
			ofproto = datapath.ofproto

			paths = []

			self.syn.append(identifier)

			self.subflows[identifier] = {'tokenb': int(hexopt[4:][:8], 16),
												'noncea': hexopt[12:],
												'ip_src': ip.src,
												'ip_dst': ip.dst,
												'tp_src': tcp_pkt.src_port,
												'tp_dst': tcp_pkt.dst_port,
												'main': False,
										 		'paths': paths
												}

			# Send B->A traffic to controller
			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.dst, ipv4_dst=ip.src,
									tcp_src=tcp_pkt.dst_port,tcp_dst=tcp_pkt.src_port,
									tcp_flags=0x012)
			actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
			self.add_flow(datapath, 2, match, actions)

	def mp_join_syn_ack(self, datapath, tcp_pkt, ip, hexopt):
		identifier = ip.dst + ip.src + str(tcp_pkt.dst_port) + str(tcp_pkt.src_port)

		if identifier not in self.synack:
			print "MP_JOIN SYN-ACK"

			self.synack.append(identifier)

			ofproto = datapath.ofproto
			parser = datapath.ofproto_parser

			self.subflows[identifier]['trunhash'] = int(hexopt[4:][:16], 16)
			self.subflows[identifier]['nonceb'] = hexopt[20:]

			# Send A->B traffic to controller
			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.dst, ipv4_dst=ip.src,
									tcp_src=tcp_pkt.dst_port, tcp_dst=tcp_pkt.src_port,
									tcp_flags=0x010)
			actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
			self.add_flow(datapath, 2, match, actions)

			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.src, ipv4_dst=ip.dst,
									tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port,
									tcp_flags=0x012)
			self.del_flow(datapath, match)

	def mp_join_ack(self, datapath, tcp_pkt, ip, src, dst, hexopt, ev):

		identifier = ip.src + ip.dst + str(tcp_pkt.src_port) + str(tcp_pkt.dst_port)

		if identifier not in self.ack:
			print "MP_JOIN ACK"

			connection = ""

			self.ack.append(identifier)

			# Zmazem pravidlo pre ACK v tomto smere
			parser = datapath.ofproto_parser
			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.src, ipv4_dst=ip.dst,
									tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port,
									tcp_flags=0x010)
			self.del_flow(datapath, match)

			# Send B->A traffic to controller
			ofproto=datapath.ofproto
			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_flags=0x002)
			actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
			self.add_flow(datapath, 2, match, actions)

			hmachash = self.subflows[identifier]['hmachash'] = hexopt[4:]

			my_tokenb = self.subflows[identifier]['tokenb']

			for ident, value in self.subflows.iteritems():
				if value['main'] and value['tokenb'] == my_tokenb:
					connection = ident
			#print "Connection ID: ", connection

			keyhmac = binascii.unhexlify(self.subflows[connection]['keya'] + self.subflows[connection]['keyb'])
			message = binascii.unhexlify(self.subflows[identifier]['noncea'] + self.subflows[identifier]['nonceb'])

			# Generate hash.
			vysledok = hmac.new(keyhmac, message, hashlib.sha1).hexdigest()

			# Compare generated HASH to the one from MP_JOIN ACK.
			if vysledok == hmachash:
				paths = sorted(list(nx.all_simple_paths(self.net, src, dst)),key=len)

				connection_paths = self.subflows[connection]['paths']

				node_disjoint_test = copy.deepcopy(paths)
				edge_disjoint_test = copy.deepcopy(paths)
				chosen_path = 0

				for p in node_disjoint_test:
					node_disjoint_path = copy.deepcopy(self.are_node_disjoint(p, connection_paths))
					if node_disjoint_path != 0:
						#print "Found node-disjoint path."
						chosen_path = node_disjoint_path
						self.subflows[connection]['paths'].append(chosen_path)
						self.subflows[identifier]['paths'].append(chosen_path)
						break

				if chosen_path == 0:
					#print "No node-disjoint paths available. Looking for edge-disjoint paths."
					for p in edge_disjoint_test:
						edge_disjoint_path = copy.deepcopy(self.are_edge_disjoint(p, connection_paths))
						if edge_disjoint_path != 0:
							self.subflows[connection]['paths'].append(chosen_path)
							self.subflows[identifier]['paths'].append(chosen_path)
							break

				if chosen_path == 0:
					#print "Neither node-disjoint paths or edge-disjoint paths were found. Using least used shortest path of connection."
					chosen_path = nx.shortest_path(self.net,src,dst)
					self.subflows[connection]['paths'].append(chosen_path)
					self.subflows[identifier]['paths'].append(chosen_path)

				#print "All paths: "
				for k, v in self.subflows.iteritems():
					print k, ": ", v['paths']

				#del self.subflows[identifier]
				#del self.subflows[connection]

				self.install_path(datapath, tcp_pkt, ip, chosen_path)

	def install_path(self, datapath, tcp_pkt, ip, cesta):
		parser = datapath.ofproto_parser
		fullpath = copy.deepcopy(cesta)
		tmppath = cesta[1:-1]
		print "Installing path from", ip.src, "to", ip.dst, "and backwards. Path is: ", fullpath
		for s in tmppath:
			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.src,
									ipv4_dst=ip.dst,
									tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port)
			next = fullpath[fullpath.index(s) + 1]
			out_port = self.net[s][next]['port']
			actions = [parser.OFPActionOutput(out_port)]
			self.add_flow(get_datapath(self, s), 4, match, actions)

			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.dst,
									ipv4_dst=ip.src,
									tcp_src=tcp_pkt.dst_port, tcp_dst=tcp_pkt.src_port)
			prev = fullpath[fullpath.index(s) - 1]
			out_port = self.net[s][prev]['port']
			actions = [parser.OFPActionOutput(out_port)]
			self.add_flow(get_datapath(self, s), 4, match, actions)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		"""
		Execute this when packet is sent to controller.
		"""

		msg = ev.msg
		datapath = msg.datapath

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		src = eth.src
		dst = eth.dst
		in_port = msg.match['in_port']
		dpid = datapath.id

		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		self.mac_to_port.setdefault(dpid, {})

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			return

		if self.break_broadcast_storm(pkt, src, dst, datapath, in_port):
			return

		ip = pkt.get_protocol(ipv4.ipv4)

		tcp_pkt = pkt.get_protocol(tcp.tcp)

		# If TCP
		if tcp_pkt:
			options = tcp_pkt.option
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
							if tcp_pkt.bits == 2:
								self.mp_capable_syn(datapath,tcp_pkt, ip, src, dst, hexopt)
							elif tcp_pkt.bits == 18:
								self.mp_capable_syn_ack(datapath,tcp_pkt, ip, src, dst, hexopt)
							elif tcp_pkt.bits == 16:
								self.mp_capable_ack(datapath,tcp_pkt, ip, src, dst, hexopt)
						# MP_JOIN
						elif subtype == "10" or subtype == "11":
							if tcp_pkt.bits == 2:
								self.mp_join_syn(datapath, tcp_pkt, ip, hexopt)
							elif tcp_pkt.bits == 18:
								self.mp_join_syn_ack(datapath,tcp_pkt, ip, hexopt)
							elif tcp_pkt.bits == 16:
								self.mp_join_ack(datapath, tcp_pkt, ip, src, dst, hexopt,ev)

		if src not in self.net:
			self.net.add_node(src)
			self.net.add_edge(dpid, src, port=in_port)
			self.net.add_edge(src, dpid)

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

		#for link in links_list:
		#	print link.src.port_no

		self.net.add_edges_from(links)
		links = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)

