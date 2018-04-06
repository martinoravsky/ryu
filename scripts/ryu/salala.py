import binascii
import copy
import hashlib
import hmac
import random
import networkx as nx
from mysql.connector import Error
from connection import connect
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
		self.mpcs = []
		self.mpcsa = []
		self.mpca = []
		self.mpjs = []
		self.mpjsa = []
		self.mpja = []

	def store_path(self, path,count):
		pathstr = " ".join(str(x) for x in path)
		values = {'nodes': pathstr,'count': count}
		query = "INSERT into mptcp.path (nodes,count) values('{nodes}',{count});"
		return self.execute_insert(query.format(**values))

	def remove_path(self, path, conn_id):
		pathstr = " ".join(str(x) for x in path)
		values = {'nodes': pathstr, 'conn_id':conn_id}
		query = "delete from path where '');"

	def execute_delete(self, query):
		"""
		Connect to MySQL database and execute DELETE

		"""
		last_id = 0
		try:
			conn = connect()
			if conn.is_connected():
				cursor = conn.cursor()
				cursor.execute(query)
		except Error as e:
			print(e)
		finally:
			conn.commit()
			conn.close()

	def execute_insert(self, query):
		"""
		Connect to MySQL database and execute INSERT

		"""
		last_id = 0
		try:
			conn = connect()
			if conn.is_connected():
				cursor = conn.cursor()
				cursor.execute(query)
				last_id = cursor.lastrowid
		except Error as e:
			print(e)
		finally:
			conn.commit()
			conn.close()
		return last_id

	def execute_select(self, query):
		"""
		Connect to MySQL Database and execute SELECT

		"""
		try:
			conn = connect()
			if conn.is_connected():
				cursor = conn.cursor()
				cursor.execute(query)
				result = cursor.fetchall()
				return result
		except Error as e:
			print(e)
		finally:
			conn.commit()
			conn.close()

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
		self.add_flow(datapath, 2, match, actions)

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
		four_tuple = (ip.src, ip.dst, tcp_pkt.src_port, tcp_pkt.dst_port)
		if four_tuple not in self.mpcs:
			print "MP_CAPABLE SYN"
			self.mpcs.append(four_tuple)

			# Sender's token is a SHA1 truncated hash of the key.
			tokena = int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8], 16)

			ofproto = datapath.ofproto
			parser = datapath.ofproto_parser

			# Vytvorim pravidlo pre SYN-ACK na opacnom smere
			match = parser.OFPMatch(eth_type=0x0800,
									ip_proto=6,
									ipv4_src=ip.dst,
									ipv4_dst=ip.src,
									tcp_flags=0x012)
			actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
			self.add_flow(datapath, 2, match, actions)

			# Sender's key.
			keya = hexopt[4:]

			# Store IPs, ports, sender's key and sender's token.
			values = {'tsrc': ip.src, 'tdst': ip.dst, 'keya': keya, 'tokena': tokena,
					  'htsrc_port': tcp_pkt.src_port, 'htdst_port': tcp_pkt.dst_port, 'src': src, 'dst': dst}
			query = "replace INTO mptcp.conn \
							(ip_src,ip_dst,keya,tokena,tcp_src,tcp_dst,src,dst) \
							values('{tsrc}','{tdst}','{keya}',{tokena},{htsrc_port},{htdst_port},'{src}','{dst}');"
			self.execute_insert(query.format(**values))
		else:
			print "Already processed MP_CAPABLE SYN"

	def mp_capable_syn_ack(self, datapath, tcp_pkt, ip, src, dst, hexopt):
		# Receiver's token is a SHA1 truncated hash of the key.
		four_tuple = (ip.src, ip.dst, tcp_pkt.src_port, tcp_pkt.dst_port)
		if four_tuple not in self.mpcsa:
			#del self.pending_synack[self.pending_synack.index((ip.dst,ip.src,tcp_pkt.dst_port,tcp_pkt.src_port))]
			print "MP_CAPABLE SYN-ACK"
			self.mpcsa.append(four_tuple)
			tokenb = int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8], 16)

			# Vytvorim pravidlo pre ACK v opacnom smere
			ofproto = datapath.ofproto
			parser = datapath.ofproto_parser
			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.dst, ipv4_dst=ip.src,
									tcp_flags=0x010)
			actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
			self.add_flow(datapath, 2, match, actions)

			# Zmazem pravidlo pre SYN-ACK v tomto smere
			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.src, ipv4_dst=ip.dst,
									tcp_flags=0x012)
			self.del_flow(datapath, match)

			# Receiver's key.
			keyb = hexopt[4:]

			# Store receiver's key and receiver's token to the appropriate connection.
			values = {'tsrc': ip.src, 'tdst': ip.dst, 'htsrc_port': tcp_pkt.src_port,
					  'htdst_port': tcp_pkt.dst_port, 'keyb': keyb, 'tokenb': tokenb}
			query = "UPDATE mptcp.conn SET keyb='{keyb}',tokenb={tokenb} WHERE ip_src='{tdst}' AND ip_dst='{tsrc}' AND tcp_src={htdst_port} AND tcp_dst={htsrc_port};"
			self.execute_insert(query.format(**values))
		else:
			print "Already processed MP_CAPABLE SYN-ACK"

	def mp_capable_ack(self, datapath, tcp_pkt, ip, src, dst, hexopt):
		four_tuple = (ip.src, ip.dst, tcp_pkt.src_port, tcp_pkt.dst_port)
		if four_tuple not in self.mpca:
			#del self.pending_ack[self.pending_synack.index((ip.dst, ip.src, tcp_pkt.dst_port, tcp_pkt.src_port))]
			self.mpca.append(four_tuple)
			print "MP_CAPABLE ACK."
			# Zmazem pravidlo pre ACK v tomto smere
			parser = datapath.ofproto_parser
			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.src, ipv4_dst=ip.dst,
									tcp_flags=0x010)
			self.del_flow(datapath, match)

			tmp = list(nx.all_simple_paths(self.net, src, dst))

			print tmp
			# Store available paths and retreat their IDs
			ids = []
			for index, item in enumerate(tmp):
				if index == 0:
					ids.append(self.store_path(item,1))
				else:
					ids.append(self.store_path(item,0))

			print tmp

			# Get connection id:
			values = {'tsrc': ip.src, 'tdst': ip.dst, 'htsrc_port': tcp_pkt.src_port,
					  'htdst_port': tcp_pkt.dst_port}
			query = "SELECT id from mptcp.conn where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port};"
			conn_id = self.execute_select(query.format(**values))[0][0]

			# Add entries to junction table.
			for path_id in ids:
				values = {'conn_id': conn_id, 'path_id': path_id}
				query = "INSERT into conn_path (conn_id, path_id) values ({conn_id},{path_id})"
				self.execute_insert(query.format(**values))

			# Sort paths by their length
			path = sorted(tmp, key=len)[0]

			self.install_path(datapath, tcp_pkt, ip, path)
		else:
			print "Already processed MP_CAPABLE ACK"

	def mp_join_syn(self, datapath, tcp_pkt, ip, hexopt):
		four_tuple = (ip.src, ip.dst, tcp_pkt.src_port, tcp_pkt.dst_port)
		if four_tuple not in self.mpjs:
			self.mpjs.append(four_tuple)
			print "MP_JOIN SYN"
			ofproto = datapath.ofproto
			parser = datapath.ofproto_parser
			# Receiver's token. From the MPTCP connection.
			tokenb = int(hexopt[4:][:8], 16)

			# Sender's nonce.
			noncea = hexopt[12:]

			# Store IPs, ports, sender's nonce into subflow table.
			values = {'tsrc': ip.src, 'tdst': ip.dst, 'tokenb': tokenb, 'noncea': noncea,
					  'htsrc_port': tcp_pkt.src_port, 'htdst_port': tcp_pkt.dst_port}
			query = "replace INTO mptcp.subflow (ip_src,ip_dst,tokenb,noncea,tcp_src,tcp_dst) values('{tsrc}','{tdst}',{tokenb},'{noncea}',{htsrc_port},{htdst_port});"
			self.execute_insert(query.format(**values))

			# Send B->A traffic to controller
			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.dst, ipv4_dst=ip.src,
									tcp_flags=0x012)
			actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
			self.add_flow(datapath, 2, match, actions)
		else:
			print "Already processed MP_JOIN SYN"

	def mp_join_syn_ack(self, datapath, tcp_pkt, ip, hexopt):
		four_tuple = (ip.src, ip.dst, tcp_pkt.src_port, tcp_pkt.dst_port)
		if four_tuple not in self.mpjsa:
			print "MP_JOIN SYN-ACK"
			self.mpjsa.append(four_tuple)
			ofproto = datapath.ofproto
			parser = datapath.ofproto_parser
			# Receiver's truncated HASH.
			trunhash = int(hexopt[4:][:16], 16)

			# Receiver's nonce.
			nonceb = hexopt[20:]

			# Store truncated HASH and receiver's nonce into appropriate subflow.
			values = {'tsrc': ip.src, 'tdst': ip.dst, 'htsrc_port': tcp_pkt.src_port,
					  'htdst_port': tcp_pkt.dst_port, 'trunhash': trunhash, 'nonceb': nonceb}
			query = "UPDATE mptcp.subflow SET trunhash={trunhash},nonceb='{nonceb}' WHERE ip_src='{tdst}' AND ip_dst='{tsrc}' AND tcp_src={htdst_port} AND tcp_dst={htsrc_port};"
			self.execute_insert(query.format(**values))

			# Send A->B traffic to controller
			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.dst, ipv4_dst=ip.src,
									tcp_flags=0x010)
			actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
			self.add_flow(datapath, 2, match, actions)

			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.src, ipv4_dst=ip.dst,
									tcp_flags=0x012)
			self.del_flow(datapath, match)
		else:
			print "Already processed MP_JOIN SYN-ACK"

	def mp_join_ack(self, datapath, tcp_pkt, ip, src, dst, hexopt):
		four_tuple = (ip.src, ip.dst, tcp_pkt.src_port, tcp_pkt.dst_port)
		if four_tuple not in self.mpja:
			print "MP_JOIN ACK"
			self.mpja.append(four_tuple)

			# Sender's HASH.
			hmachash = hexopt[4:]

			# Store sender's HASH to appropriate subflow.
			values = {'tsrc': ip.src, 'tdst': ip.dst, 'htsrc_port': tcp_pkt.src_port,
					  'htdst_port': tcp_pkt.dst_port, 'hmachash': hmachash}
			query = "UPDATE mptcp.subflow SET hash='{hmachash}' WHERE ip_src='{tsrc}' AND ip_dst='{tdst}' AND tcp_src={htsrc_port} AND tcp_dst={htdst_port};"
			self.execute_insert(query.format(**values))

			# Select keys from appropriate connection based on receiver's token.
			values = {'tsrc': ip.src, 'tdst': ip.dst, 'htsrc_port': tcp_pkt.src_port,
					  'htdst_port': tcp_pkt.dst_port}
			query = "SELECT keya,keyb from conn where tokenb in (SELECT tokenb from subflow where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port});"
			keys = self.execute_select(query.format(**values))

			# Select nonces for current subflow.
			values = {'tsrc': ip.src, 'tdst': ip.dst, 'htsrc_port': tcp_pkt.src_port,
					  'htdst_port': tcp_pkt.dst_port}
			query = "SELECT noncea,nonceb from subflow where ip_src='{tsrc}' AND ip_dst='{tdst}' AND tcp_src={htsrc_port} AND tcp_dst={htdst_port};"
			nonces = self.execute_select(query.format(**values))

			# Key for generating HMAC is a concatenation of two keys. Message is a concatenation of two nonces.
			keyhmac = binascii.unhexlify(keys[0][0] + keys[0][1])
			message = binascii.unhexlify(nonces[0][0] + nonces[0][1])

			# Generate hash.
			vysledok = hmac.new(keyhmac, message, hashlib.sha1).hexdigest()

			# Compare generated HASH to the one from MP_JOIN ACK.
			if vysledok == hmachash:
				# Get connection ID based on tokens.
				values = {'tsrc': ip.src, 'tdst': ip.dst, 'htsrc_port': tcp_pkt.src_port,
						  'htdst_port': tcp_pkt.dst_port}
				query = "SELECT id from conn where tokenb in (SELECT tokenb from subflow where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port});"
				conn_id = self.execute_select(query.format(**values))[0][0]

				# Insert connection ID to a current subflow.
				values = {'tsrc': ip.src, 'tdst': ip.dst, 'htsrc_port': tcp_pkt.src_port, 'htdst_port': tcp_pkt.dst_port, 'id': conn_id}
				query = "update subflow set connid = {id} where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port};"
				self.execute_insert(query.format(**values))

				# Get src and dst mac of appropriate connection.
				query = "select src,dst from conn join subflow on subflow.connid=conn.id where conn.id=(select connid from subflow where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port}) group by src;"
				result = self.execute_select(query.format(**values))
				srcmac = result[0][0]
				dstmac = result[0][1]
				print srcmac
				print dstmac

				# Find least used path and also the shortest.
				values = {'conn_id': conn_id}
				query = "select path_id, count, c.id, p.nodes from conn c inner join conn_path cp on c.id = cp.conn_id inner join path p on p.id = cp.path_id where c.id = {conn_id} order by count asc;"
				print "Hladanie najmenej pouzitej a zaroven najkratsej cesty!"
				cesty = self.execute_select(query.format(**values))

				print cesty
				path_id = cesty[0][0]
				final_path = cesty[0][3].split(' ')

				# Update count for chosen path.
				values = {'path_id':path_id}
				query = "update path set count = count + 1 where id = {path_id}"
				self.execute_insert(query.format(**values))

				# Parse paths, change MAC addresses
				to_use = copy.deepcopy(final_path)[1:-1]
				to_use = [int(x) for x in to_use]
				to_use.insert(0,src)
				to_use.insert(len(to_use), dst)
				print to_use

				self.install_path(datapath, tcp_pkt, ip, to_use)
		else:
			print "Already processed MP_JOIN ACK"

	def install_path(self, datapath, tcp_pkt, ip, cesta):
		parser = datapath.ofproto_parser
		fullpath = cesta
		tmppath = cesta[1:-1]
		print "Installing path from", ip.src, "to", ip.dst, "and backwards."
		for s in tmppath:
			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.src,
									ipv4_dst=ip.dst,
									tcp_src=tcp_pkt.src_port, tcp_dst=tcp_pkt.dst_port)
			next = fullpath[fullpath.index(s) + 1]
			out_port = self.net[s][next]['port']
			actions = [parser.OFPActionOutput(out_port)]
			self.add_flow(get_datapath(self, s), 3, match, actions)

			match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=ip.dst,
									ipv4_dst=ip.src,
									tcp_src=tcp_pkt.dst_port, tcp_dst=tcp_pkt.src_port)
			prev = fullpath[fullpath.index(s) - 1]
			out_port = self.net[s][prev]['port']
			actions = [parser.OFPActionOutput(out_port)]
			self.add_flow(get_datapath(self, s), 3, match, actions)

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

		#self.logger.info("Packet arrived at switch no. %d, source MAC is: %s, destination MAC is: %s, in_port is: %s",
		#				 datapath.id, src, dst, in_port)

		ip = pkt.get_protocol(ipv4.ipv4)

		#if ip:
		#	print 'Source IP address: ', ip.src
		#	print 'Destination IP address: ', ip.dst

		tcp_pkt = pkt.get_protocol(tcp.tcp)

		# If TCP
		if tcp_pkt:
			# print 'zdrojovy port: ', tcp_pkt.src_port
			# print 'destination port: ', tcp_pkt.dst_port
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
								self.mp_capable_syn(datapath,tcp_pkt, ip, src, dst,hexopt)
							elif tcp_pkt.bits == 18:
								self.mp_capable_syn_ack(datapath,tcp_pkt, ip, src, dst,hexopt)
							elif tcp_pkt.bits == 16:
								self.mp_capable_ack(datapath,tcp_pkt, ip, src, dst,hexopt)
						# MP_JOIN
						elif subtype == "10" or subtype == "11":
							if tcp_pkt.bits == 2:
								self.mp_join_syn(datapath, tcp_pkt, ip,hexopt)
							elif tcp_pkt.bits == 18:
								self.mp_join_syn_ack(datapath,tcp_pkt, ip,hexopt)
							elif tcp_pkt.bits == 16:
								self.mp_join_ack(datapath, tcp_pkt, ip, src, dst,hexopt)

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

