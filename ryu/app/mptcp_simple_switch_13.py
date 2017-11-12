# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	 http://www.apache.org/licenses/LICENSE-2.0
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
import binascii
import hashlib,hmac
import os
import mysql.connector
from mysql.connector import Error


class L2switch(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

	def executeInsert(self,query):
		try:
			conn = mysql.connector.connect(host='localhost',
											database='mptcp',
											user='debian-sys-maint',
											password='QkrL9GepDeTtoTsM')
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
		try:
			conn = mysql.connector.connect(host='localhost',
											database='mptcp',
											user='debian-sys-maint',
											password='QkrL9GepDeTtoTsM')
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





	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		# install table-miss flow entry
		#
		# We specify NO BUFFER to max_len of the output action due to
		# OVS bug. At this moment, if we specify a lesser number, e.g.,
		# 128, OVS will send Packet-In with invalid buffer_id and
		# truncated packet data. In that case, we cannot output packets
		# correctly.  The bug has been fixed in OVS v2.1.0.
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

		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]

		if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			# ignore lldp packet
			return

		dst = eth.dst
		src = eth.src


		self.logger.info("Na controller dorazi paket. Predtym prisiel na Switch cislo %s, na port %s. Dst: %s, Src: %s",datapath.id,in_port,dst,src)

		t = pkt.get_protocol(ipv4.ipv4)

		if t:
			print 'zdrojova ip: ',t.src
			print 'dest ip: ',t.dst

		ht = pkt.get_protocol(tcp.tcp)

		if ht:
			print 'zdrojovy port: ',ht.src_port
			print 'destination port: ',ht.dst_port
			print datapath.id
			options = ht.option
			if options:
				if len(options) > 0:
					for opt in options:
						if opt.kind == 30: # MPTCP
							hexopt = binascii.hexlify(opt.value)
							subtype = hexopt[:2]
							#print("Vypisujem hexopt: ",hexopt)
							#print("Vypisujem subtype: ",subtype)
							if subtype == "00":          # MP_CAPABLE
								if ht.bits == 2:            # SYN
									# Pridanie flowu pre ACK od hosta do hostb
									command = 'ovs-ofctl -OOpenFlow13 add-flow s1 "table=0,priority=2,eth_dst='+dst+',tcp,tcp_flags=0x002,actions=CONTROLLER:65535"'
									os.system(command)
									command = 'ovs-ofctl -OOpenFlow13 add-flow s1 "table=0,priority=2,eth_dst='+src+',tcp,tcp_flags=0x012,actions=CONTROLLER:65535"'
									os.system(command)
									#self.logger.info("Pridal som flow pre SYN-ACK z IP %s do IP %s. Ethsrc: %s, Ethdst: %s.",t.src,t.dst,dst,src)
									print("MP_CAPABLE SYN. Sender's key: ", int(hexopt[4:],16))
									print("MP_CAPABLE SYN. Subflow token generated from key: ", int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8],16))
									
									keya = hexopt[4:]
									tokena = int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8],16)
									
									values = {'tsrc':t.src,'tdst':t.dst,'keya':keya,'tokena':tokena,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port}
									query = "INSERT INTO mptcp.conn (ip_src,ip_dst,keya,tokena,tcp_src,tcp_dst) values('{tsrc}','{tdst}','{keya}',{tokena},{htsrc_port},{htdst_port});"
									self.executeInsert(query.format(**values))

								elif ht.bits == 18:         # SYN-ACK
									#self.logger.info("Pridal som flow pre ACK z IP %s do IP %s. Ethsrc: %s, Ethdst: %s.",t.src,t.dst,src,dst)
									command = 'ovs-ofctl -OOpenFlow13 add-flow s1 "table=0,priority=2,eth_dst='+src+',tcp,tcp_flags=0x010,actions=CONTROLLER:65535"'
									os.system(command)
									#self.logger.info("Prisiel MP_CAPABLE SYN-ACK. Prisiel lebo mam pravidlo pre neho. Toto pravidlo teraz zmazem.")
									keyb = hexopt[4:]
									tokenb = int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8],16)
									
									values = {'tsrc':t.src,'tdst':t.dst,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port,'keyb':keyb,'tokenb':tokenb}
									query = "UPDATE mptcp.conn SET keyb='{keyb}',tokenb={tokenb} WHERE ip_src='{tdst}' AND ip_dst='{tsrc}' AND tcp_src={htdst_port} AND tcp_dst={htsrc_port};"
									self.executeInsert(query.format(**values))

									#print(query.format(**values))
									print("MP_CAPABLE SYN-ACK. Receivers'key: ", int(hexopt[4:],16))
									print("MP_CAPABLE SYN-ACK. Subflow token generated from key: ", int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8],16))
								elif ht.bits == 16:         # ACK
									self.logger.info("Prisiel MP_CAPABLE ACK. Prisiel lebo mam pravidlo pre neho. Toto pravidlo teraz zmazem.")
									print("MP_CAPABLE ACK. Already have keys.")
									command = 'ovs-ofctl -OOpenFlow13 del-flows s1 "eth_dst='+dst+',tcp,tcp_flags=0x010"'
									os.system(command)
							elif subtype == "10" or subtype == "11":        # MP_JOIN
								if ht.bits == 2:            # SYN
									command = 'ovs-ofctl -OOpenFlow13 add-flow s1 "table=0,priority=2,eth_dst='+dst+',tcp,tcp_flags=0x002,actions=CONTROLLER:65535"'
									os.system(command)
									command = 'ovs-ofctl -OOpenFlow13 add-flow s1 "table=0,priority=2,eth_dst='+src+',tcp,tcp_flags=0x012,actions=CONTROLLER:65535"'
									os.system(command)
									#self.logger.info("Pridal som flow pre JOIN SYN-ACK z IP %s do IP %s. Ethsrc: %s, Ethdst: %s.",t.src,t.dst,dst,src)
									tokenb = int(hexopt[4:][:8],16)
									noncea = hexopt[12:]
									
									values = {'tsrc':t.src,'tdst':t.dst,'tokenb':tokenb,'noncea':noncea,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port}
									query = "INSERT INTO mptcp.subflow (ip_src,ip_dst,tokenb,noncea,tcp_src,tcp_dst) values('{tsrc}','{tdst}',{tokenb},'{noncea}',{htsrc_port},{htdst_port});"
									self.executeInsert(query.format(**values))

									print("MP_JOIN SYN. Receiver's token: ", int(hexopt[4:][:8],16))
									print("MP_JOIN SYN. Sender's nonce: ", int(hexopt[12:],16))
								elif ht.bits == 18:         # SYN-ACK
									#self.logger.info("Prisiel MP_JOIN SYN-ACK. Prisiel lebo mam pravidlo pre neho. Toto pravidlo teraz zmazem.")
									command = 'ovs-ofctl -OOpenFlow13 add-flow s1 "table=0,priority=2,eth_dst='+src+',tcp,tcp_flags=0x010,actions=CONTROLLER:65535"'
									os.system(command)
									#self.logger.info("Pridal som flow pre JOIN ACK z IP %s do IP %s. Ethsrc: %s, Ethdst: %s.",t.dst,t.src,src,dst)

									trunhash = int(hexopt[4:][:16],16)
									nonceb = hexopt[20:]
									print("MP_JOIN SYN-ACK. Sender's truncated HMAC :", int(hexopt[4:][:16],16))
									print("MP_JOIN SYN-ACK. Sender's nonce: ", int(hexopt[20:],16))
									
									values = {'tsrc':t.src,'tdst':t.dst,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port,'trunhash':trunhash,'nonceb':nonceb}
									query = "UPDATE mptcp.subflow SET trunhash={trunhash},nonceb='{nonceb}' WHERE ip_src='{tdst}' AND ip_dst='{tsrc}' AND tcp_src={htdst_port} AND tcp_dst={htsrc_port};"
									self.executeInsert(query.format(**values))
								elif ht.bits == 16:         # ACK
									hmachash = hexopt[4:]
									values = {'tsrc':t.src,'tdst':t.dst,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port,'hmachash':hmachash}
									query = "UPDATE mptcp.subflow SET hash='{hmachash}' WHERE ip_src='{tsrc}' AND ip_dst='{tdst}' AND tcp_src={htsrc_port} AND tcp_dst={htdst_port};"
									self.executeInsert(query.format(**values))
									#self.logger.info("Prisiel MP_JOIN ACK. Prisiel lebo mam pravidlo pre neho. Toto pravidlo teraz zmazem.")
									print("MP_JOIN ACK. Sender's HMAC :", hexopt[4:])
									command = 'ovs-ofctl -OOpenFlow13 del-flows s1 "eth_dst='+dst+',tcp,tcp_flags=0x010"'
									os.system(command)

									# Pocitanie hashov
									values = {'tsrc':t.src,'tdst':t.dst,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port}
									query = "SELECT keya,keyb from conn where tokenb in (SELECT tokenb from subflow where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port});"
									keys = self.executeSelect(query.format(**values))
									print(query.format(**values))
									print(keys)
								
									values = {'tsrc':t.src,'tdst':t.dst,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port}
									query = "SELECT noncea,nonceb from subflow where ip_src='{tsrc}' AND ip_dst='{tdst}' AND tcp_src={htsrc_port} AND tcp_dst={htdst_port};"
									nonces = self.executeSelect(query.format(**values))
									print(query.format(**values))
									print(nonces)
									print(keys[0]+keys[1])
									print(nonces[0]+nonces[1])

									key = binascii.unhexlify(keys[0]+keys[1])
									msg = binascii.unhexlify(nonces[0]+nonces[1])
									vysledok = hmac.new(key,msg, hashlib.sha1).hexdigest()
									print(vysledok)
									if vysledok == hmachash:
										values = {'tsrc':t.src,'tdst':t.dst,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port}
										query = "SELECT id from conn where tokenb in (SELECT tokenb from subflow where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port});"
										ids = self.executeSelect(query.format(**values))[0]
										values = {'tsrc':t.src,'tdst':t.dst,'htsrc_port':ht.src_port,'htdst_port':ht.dst_port, 'id':ids}
										query = "update subflow set connid = {id} where ip_src='{tsrc}' and ip_dst='{tdst}' and tcp_src={htsrc_port} and tcp_dst={htdst_port};"
										self.executeInsert(query.format(**values))
			if ht.src_port == 80:
				print
				'HTTP!!!'
			elif ht.dst_port == 80:
				print
				'HTTP!!!'
		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})

		self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

		# learn a mac address to avoid FLOOD next time.
		self.mac_to_port[dpid][src] = in_port

		for f in msg.match.fields:
			if f.header == ofproto_v1_3.OXM_OF_IN_PORT:
				in_port = f.value

		if src not in self.net:
			self.net.add_node(src)
			self.net.add_edge(dpid,src,port=in_port)
			self.net.add_edge(src,dpid)
		if dst in self.net:
			print(nx.shortest_path(self.net,src,dst))
			path = nx.shortest_path(self.net,src,dst)
			next = path[path.index(dpid) + 1]
			out_port = self.net[dpid][next]['port']
		else:
			out_port = ofproto.OFPP_FLOOD
			
	#	if dst in self.mac_to_port[dpid]:
	#		out_port = self.mac_to_port[dpid][dst]
	#	else:
	#		out_port = ofproto.OFPP_FLOOD

		actions = [parser.OFPActionOutput(out_port)]

		# install a flow to avoid packet_in next time
		if out_port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
			# verify if we have a valid buffer_id, if yes avoid to send both
			# flow_mod & packet_out
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
		switch_list = get_switch(self.topology_api_app, None)
		switches=[switch.dp.id for switch in switch_list]
		self.net.add_nodes_from(switches)

		links_list = get_link(self.topology_api_app, None)
		links = [(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
		self.net.add_edges_from(links)
		print(self.net.edges())
		print(links)
		print(switches)
