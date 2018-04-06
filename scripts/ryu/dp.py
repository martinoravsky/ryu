from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import tcp, ipv4, arp
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
import networkx as nx
import binascii, hashlib, hmac, os, mysql.connector
from mysql.connector import Error
from connection import connect


class L2switch(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def executeInsert(self,query):
		"""
		Connect to MySQL database and execute INSERT
		"""
		try:
			conn = connect()
			if conn.is_connected():
				print('Connected do MySQL. Query: %s',query)
				cursor = conn.cursor()
				cursor.execute(query)
		except Error as e:
			print(e)
		finally:
			conn.commit()
			conn.close()


	def executeSelect(self,query):
		"""
		Connect to MySQL Database and execute SELECT
		"""
		try:
			conn = connect()
			if conn.is_connected():
				print('Connected do MySQL. Query: %s',query)
				cursor = conn.cursor()
				cursor.execute(query)
				result = cursor.fetchone()
				return result
		except Error as e:
			print(e)
		finally:
			conn.commit()
			conn.close()


	def __init__(self, *args, **kwargs):
		"""
		Initialise everything and truncate MySQL tables
		"""
		super(L2switch, self).__init__(*args, **kwargs)
		self.mac_to_port = {}
		self.topology_api_app = self
		self.net = nx.DiGraph()
		self.nodes = {}
		self.links = {}
		self.no_of_nodes = 0
		self.no_of_links = 0
		self.i = 0
		self.executeInsert("DELETE FROM mptcp.conn;")
		self.executeInsert("DELETE FROM mptcp.subflow;")
		self.connpaths = {}
		self.file = open('out.txt', 'w')
		self.arpnet = nx.DiGraph()

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		"""
		Install table miss entry everytime new switch connects
		"""
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

		# Install flow for all TCP traffic
		match = parser.OFPMatch(eth_type=0x0800,ip_proto=6)
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										  ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 2, match, actions)

	def add_flow(self, datapath, priority, match, actions, buffer_id=None):
		"""
		Add flow to switch based on priority, match and actions
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



	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		"""
		Executes everytime a packet arrives on a controller
		"""
		# If you hit this you might want to increase
		# the "miss_send_length" of your switch
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
							  ev.msg.msg_len, ev.msg.total_len)
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		dpid = datapath.id

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			# ignore lldp packet
			return

		dst = eth.dst
		src = eth.src

		#self.logger.info("Na controller dorazi paket. Predtym prisiel na Switch cislo %s, na port %s. Dst: %s, Src: %s",datapath.id,in_port,dst,src)

		if pkt.get_protocol(arp.arp):
			if src not in self.arpnet:
				self.arpnet.add_node(src)
				self.arpnet.add_edge(dpid, src, port= in_port)
	           	self.arpnet.add_edge(src, dpid)
			if dst in self.net:
				path = nx.shortest_path(self.arpnet,src,dst)
				next = path[path.index(dpid) + 1]
				out_port=self.arpnet[dpid][next]['port']
			else:
				out_port = ofproto.OFPP_FLOOD

		else:
			t = pkt.get_protocol(ipv4.ipv4)

			if t:
				print 'zdrojova ip: ',t.src
				print 'dest ip: ',t.dst

			ht = pkt.get_protocol(tcp.tcp)


			# If TCP
			if ht:
				print 'zdrojovy port: ',ht.src_port
				print 'destination port: ',ht.dst_port

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
									match = parser.OFPMatch(eth_type=0x0800,ip_proto=6,ipv4_src=t.src,ipv4_dst=t.dst,tcp_src=ht.src_port,tcp_dst=ht.dst_port)
									actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
												  ofproto.OFPCML_NO_BUFFER)]
									self.add_flow(datapath, 3, match, actions)

									# Send B->A traffic to controller
									match = parser.OFPMatch(eth_type=0x0800,ip_proto=6,ipv4_src=t.dst,ipv4_dst=t.src,tcp_src=ht.dst_port,tcp_dst=ht.src_port)
									actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
												  ofproto.OFPCML_NO_BUFFER)]
									self.add_flow(datapath, 3, match, actions)

									# Sender's key.
									keya = hexopt[4:]

									# Sender's token is a SHA1 truncated hash of the key.
									tokena = int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8],16)

									# Store IPs, ports, sender's key and sender's token.
									values = {'tsrc':t.src,'tdst':t.dst,'keya':keya,'tokena':tokena,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port,'src':src,'dst':dst}
									query = "replace INTO mptcp.conn (ip_src,ip_dst,keya,tokena,tcp_src,tcp_dst,src,dst) values('{tsrc}','{tdst}','{keya}',{tokena},{htsrc_port},{htdst_port},'{src}','{dst}');"
									self.executeInsert(query.format(**values))
								# MP_CAPABLE SYN-ACK
								elif ht.bits == 18:
									self.logger.info("MP_CAPABLE SYN-ACK")

									# Change out_port so traffic does not go to controller anymore
									dpid=datapath.id
									match = parser.OFPMatch(eth_type=0x0800,ip_proto=6,ipv4_src=t.src,ipv4_dst=t.dst,tcp_src=ht.src_port,tcp_dst=ht.dst_port)

									if dst in self.mac_to_port[dpid]:
										out_port = self.mac_to_port[dpid][dst]
									else:
										out_port = ofproto.OFPP_FLOOD

									actions = [parser.OFPActionOutput(out_port)]
									self.add_flow(datapath, 3, match, actions)

									# Receiver's key.
									keyb = hexopt[4:]

									# Receiver's token is a SHA1 truncated hash of the key.
									tokenb = int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8],16)

									# Store receiver's key and receiver's token to the appropriate connection.
									values = {'tsrc':t.src,'tdst':t.dst,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port,'keyb':keyb,'tokenb':tokenb}
									query = "UPDATE mptcp.conn SET keyb='{keyb}',tokenb={tokenb} WHERE ip_src='{tdst}' AND ip_dst='{tsrc}' AND tcp_src={htdst_port} AND tcp_dst={htsrc_port};"
									self.executeInsert(query.format(**values))

								# MP_CAPABLE ACK
								elif ht.bits == 16:
									self.logger.info("MP_CAPABLE ACK")

									# Change out_port so traffic does not go to controller anymore
									dpid = datapath.id
									match = parser.OFPMatch(eth_type=0x0800,ip_proto=6,ipv4_src=t.src,ipv4_dst=t.dst,tcp_src=ht.src_port,tcp_dst=ht.dst_port)

									if dst in self.mac_to_port[dpid]:
										out_port = self.mac_to_port[dpid][dst]
									else:
										out_port = ofproto.OFPP_FLOOD

									actions = [parser.OFPActionOutput(out_port)]
									self.add_flow(datapath, 3, match, actions)

									command = 'ovs-ofctl -OOpenFlow13 del-flows s1 "eth_dst='+dst+',tcp,tcp_flags=0x010"'
									os.system(command)

							# MP_JOIN
							elif subtype == "10" or subtype == "11":

								# MP_JOIN SYN
								if ht.bits == 2:
									self.logger.info("MP_JOIN SYN")

									# Send A->B traffic to controller
									match = parser.OFPMatch(eth_type=0x0800,ip_proto=6,ipv4_src=t.src,ipv4_dst=t.dst,tcp_src=ht.src_port,tcp_dst=ht.dst_port)
									actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
												  ofproto.OFPCML_NO_BUFFER)]
									self.add_flow(datapath, 3, match, actions)

									# Send B->A traffic to controller
									match = parser.OFPMatch(eth_type=0x0800,ip_proto=6,ipv4_src=t.dst,ipv4_dst=t.src,tcp_src=ht.dst_port,tcp_dst=ht.src_port)
									actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
												  ofproto.OFPCML_NO_BUFFER)]
									self.add_flow(datapath, 3, match, actions)

									# Receiver's token. From the MPTCP connection.
									tokenb = int(hexopt[4:][:8],16)

									# Sender's nonce.
									noncea = hexopt[12:]

									# Store IPs, ports, sender's nonce into subflow table.
									values = {'tsrc':t.src,'tdst':t.dst,'tokenb':tokenb,'noncea':noncea,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port}
									query = "replace INTO mptcp.subflow (ip_src,ip_dst,tokenb,noncea,tcp_src,tcp_dst) values('{tsrc}','{tdst}',{tokenb},'{noncea}',{htsrc_port},{htdst_port});"
									self.executeInsert(query.format(**values))

								# MP_JOIN SYN-ACK
								elif ht.bits == 18:
									self.logger.info("MP_JOIN SYN-ACK.")

									# Change out_port so traffic does not go to controller anymore
									dpid=datapath.id
									match = parser.OFPMatch(eth_type=0x0800,ip_proto=6,ipv4_src=t.src,ipv4_dst=t.dst,tcp_src=ht.src_port,tcp_dst=ht.dst_port)

									if dst in self.mac_to_port[dpid]:
										out_port = self.mac_to_port[dpid][dst]
									else:
										out_port = ofproto.OFPP_FLOOD

									actions = [parser.OFPActionOutput(out_port)]
									self.add_flow(datapath, 3, match, actions)

									# Receiver's truncated HASH.
									trunhash = int(hexopt[4:][:16],16)

									# Receiver's nonce.
									nonceb = hexopt[20:]

									# Store truncated HASH and receiver's nonce into appropriate subflow.
									values = {'tsrc':t.src,'tdst':t.dst,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port,'trunhash':trunhash,'nonceb':nonceb}
									query = "UPDATE mptcp.subflow SET trunhash={trunhash},nonceb='{nonceb}' WHERE ip_src='{tdst}' AND ip_dst='{tsrc}' AND tcp_src={htdst_port} AND tcp_dst={htsrc_port};"
									self.executeInsert(query.format(**values))

								# MP_JOIN ACK
								elif ht.bits == 16:
									self.logger.info("MP_JOIN ACK.")

									# Change out_port so traffic does not go to controller anymore
									dpid = datapath.id
									match = parser.OFPMatch(eth_type=0x0800,ip_proto=6,ipv4_src=t.src,ipv4_dst=t.dst,tcp_src=ht.src_port,tcp_dst=ht.dst_port)

									if dst in self.mac_to_port[dpid]:
										out_port = self.mac_to_port[dpid][dst]
									else:
										out_port = ofproto.OFPP_FLOOD

									actions = [parser.OFPActionOutput(out_port)]
									self.add_flow(datapath, 3, match, actions)

									# Sender's HASH.
									hmachash = hexopt[4:]

									# Store sender's HASH to appropriate subflow.
									values = {'tsrc':t.src,'tdst':t.dst,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port,'hmachash':hmachash}
									query = "UPDATE mptcp.subflow SET hash='{hmachash}' WHERE ip_src='{tsrc}' AND ip_dst='{tdst}' AND tcp_src={htsrc_port} AND tcp_dst={htdst_port};"
									self.executeInsert(query.format(**values))

									# Select keys from appropriate connection based on receiver's token.
									values = {'tsrc':t.src,'tdst':t.dst,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port}
									query = "SELECT keya,keyb from conn where tokenb in (SELECT tokenb from subflow where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port});"
									keys = self.executeSelect(query.format(**values))

									# Select nonces for current subflow.
									values = {'tsrc':t.src,'tdst':t.dst,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port}
									query = "SELECT noncea,nonceb from subflow where ip_src='{tsrc}' AND ip_dst='{tdst}' AND tcp_src={htsrc_port} AND tcp_dst={htdst_port};"
									nonces = self.executeSelect(query.format(**values))

									# Key for generating HMAC is a concatenation of two keys. Message is a concatenation of two nonces.
									keyhmac = binascii.unhexlify(keys[0]+keys[1])
									message = binascii.unhexlify(nonces[0]+nonces[1])

									# Generate hash.
									vysledok = hmac.new(keyhmac,message, hashlib.sha1).hexdigest()
									print(vysledok)

									# Compare generated HASH to the one from MP_JOIN ACK.
									if vysledok == hmachash:

										# Get connection ID based on tokens.
										values = {'tsrc':t.src,'tdst':t.dst,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port}
										query = "SELECT id from conn where tokenb in (SELECT tokenb from subflow where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port});"
										ids = self.executeSelect(query.format(**values))[0]

										# Insert connection ID to a current subflow.
										values = {'tsrc':t.src,'tdst':t.dst,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port, 'id':ids}
										query = "update subflow set connid = {id} where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port};"
										self.executeInsert(query.format(**values))

										query = "select src,dst from conn join subflow on subflow.connid=conn.id where conn.id=(select connid from subflow where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port}) group by src;"

										result = self.executeSelect(query.format(**values))
										srcmac = result[0]
										dstmac = result[1]
										print ('srcmac = %s',srcmac)
										print ('dstmac = %s',dstmac)


			# Learn MAC addresses to avoid FLOOD.
		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})
		self.mac_to_port[dpid][src] = in_port


		if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]
		else:
			out_port = ofproto.OFPP_FLOOD

		actions = [parser.OFPActionOutput(out_port)]

		# Install flow to avoid FLOOD next time.
		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
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


	@set_ev_cls(event.EventSwitchEnter)
	def get_topology_data(self, ev):
		"""
		Get topology data. Links and switches.
		"""
		switch_list = get_switch(self.topology_api_app, None)
		switches=[switch.dp.id for switch in switch_list]
		self.net.add_nodes_from(switches)
		print("Switches: ", switches)

		links_list = get_link(self.topology_api_app, None)
		print("Links_list from ryu: ",links_list)

		links = [(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		print("Linky: ",links)

		self.net.add_edges_from(links)

		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		print("Linky znova: ",links)
		self.net.add_edges_from(links)
		print("Linky z programu: ",self.net.edges())
		print("Nodes z programu: ",self.net.nodes())


		self.arpnet.add_nodes_from(switches)
		linksarp_list = get_link(self.topology_api_app, None)
		linksarp = [(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in linksarp_list]

		self.arpnet.add_edges_from(linksarp)

		linksarp = [(link.dst.dpid, link.src.dpid, {'port': link.dst.port_no}) for link in linksarp_list]
		self.arpnet.add_edges_from(linksarp)

		self.arpnet = nx.minimum_spanning_tree(self.net.to_undirected())

		self.arpnet = nx.to_directed(self.arpnet)

		print ("arpnet: ", self.arpnet.edges)











