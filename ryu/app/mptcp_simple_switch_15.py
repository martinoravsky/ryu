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
from ryu.ofproto import ofproto_v1_5 as ofproto
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import tcp, ipv4
#from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
#from ryu.topology import event, switches
#import networkx as nx
import binascii
import hashlib
import commands
import os

class L2switch(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto.OFP_VERSION]

	def __init__(self, *args, **kwargs):
		super(L2switch, self).__init__(*args, **kwargs)
		self.mac_to_port = {}

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

#		match = parser.OFPMatch(eth_type=0x800,ip_proto=6,tcp_flags=0x002)
#		match1 = parser.OFPMatch(eth_type=0x800,ip_proto=6,tcp_flags=0x012)
#		match2 = parser.OFPMatch(eth_type=0x800,ip_proto=6,tcp_flags=0x010)
#		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
#										  ofproto.OFPCML_NO_BUFFER)]
#		self.add_flow(datapath, 2, match, actions)
#		self.add_flow(datapath, 2, match1, actions)
#		self.add_flow(datapath, 2, match2, actions)


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

		self.logger.info("Na controller dorazil paket. Predtym prisiel na Switch cislo %s, na port %s. Dst: %s, Src: %s",datapath.id,in_port,dst,src)

		t = pkt.get_protocol(ipv4.ipv4)

		if t:
			print 'zdrojova ip: ',t.src
			print 'dest ip: ',t.dst

		ht = pkt.get_protocol(tcp.tcp)

		if ht:
			print 'zdrojovy port: ',ht.src_port
			print 'destination port: ',ht.dst_port

			options = ht.option
			if options:
				if len(options) > 0:
					for opt in options:
						if opt.kind == 30: # MPTCP
							hexopt = binascii.hexlify(opt.value)
							if hexopt[:2] == "00":          # MP_CAPABLE
								if ht.bits == 2:            # SYN
									# Pridanie flowu pre ACK od hosta do hostb

									dpid = datapath.id
									#match = parser.OFPMatch(eth_type=0x800,eth_dst=dst, ip_proto=6,ipv4_src=t.src,ipv4_dst=t.dst,tcp_src=ht.src_port,tcp_dst=ht.dst_port,tcp_flags=0x010)
									match = parser.OFPMatch(eth_type=0x800,eth_dst=dst, ip_proto=6,tcp_flags=0x010)
									actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
									self.add_flow(datapath, 2, match, actions)
									self.logger.info("Pridal som flow pre ACK src: %s, dst: %s:, src_port: %d, dst_port: %d, src_ip: %s, dst_ip: %s", src,dst,ht.src_port,ht.dst_port,t.src,t.dst)

						#			# Pridanie flowu pre SYN-ACK od hostb do hosta
									#match = parser.OFPMatch(eth_type=0x800,eth_dst=src, ip_proto=6,ipv4_src=t.dst,ipv4_dst=t.src,tcp_src=ht.dst_port,tcp_dst=ht.src_port,tcp_flags=0x012)
									match = parser.OFPMatch(eth_type=0x800,eth_dst=src, ip_proto=6,tcp_flags=0x012)
									actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
									self.add_flow(datapath, 2, match, actions)
									self.logger.info("Pridal som flow pre SYN-ACK src: %s, dst: %s:, src_port: %d, dst_port: %d, src_ip: %s, dst_ip: %s", src,dst,ht.dst_port,ht.src_port,t.dst,t.src)

									keya = int(hexopt[4:],16)
									tokena = int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8],16)
									print("MP_CAPABLE SYN. Sender's key: ", int(hexopt[4:],16))
									print("MP_CAPABLE SYN. Subflow token generated from key: ", int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8],16))
								elif ht.bits == 18:         # SYN-ACK
									self.logger.info("Prisiel MP_CAPABLE SYN-ACK. Prisiel lebo mam pravidlo pre neho. Toto pravidlo teraz zmazem.")
							#		string = 'ovs-ofctl -OOpenFlow15 del-flows s1 "eth_dst='+dst+',tcp_flags=0x012"'
							#		os.system(string)
									keyb = int(hexopt[4:],16)
									tokenb = int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8],16)
									print("MP_CAPABLE SYN-ACK. Receivers'key: ", int(hexopt[4:],16))
									print("MP_CAPABLE SYN-ACK. Subflow token generated from key: ", int(hashlib.sha1(binascii.unhexlify(hexopt[4:])).hexdigest()[:8],16))
								elif ht.bits == 16:         # ACK
									self.logger.info("Prisiel MP_CAPABLE ACK. Prisiel lebo mam pravidlo pre neho. Toto pravidlo teraz zmazem.")
							#		string = 'ovs-ofctl -OOpenFlow15 del-flows s1 "eth_dst='+dst+', tcp_flags=0x010"'
							#		os.system(string)
									print("MP_CAPABLE ACK. Already have keys.")
							elif hexopt[:2] == "10":        # MP_JOIN
								if ht.bits == 2:            # SYN
									dpid = datapath.id
									#match = parser.OFPMatch(eth_type=0x800,eth_dst=dst, ip_proto=6,ipv4_src=t.src,ipv4_dst=t.dst,tcp_src=ht.src_port,tcp_dst=ht.dst_port,tcp_flags=0x010)
									match = parser.OFPMatch(eth_type=0x800,eth_dst=dst, ip_proto=6,tcp_flags=0x010)
									actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
									self.add_flow(datapath, 2, match, actions)
									self.logger.info("Pridal som flow pre ACK src: %s, dst: %s:, src_port: %d, dst_port: %d, src_ip: %s, dst_ip: %s", src,dst,ht.src_port,ht.dst_port,t.src,t.dst)

									#match = parser.OFPMatch(eth_type=0x800,eth_dst=src, ip_proto=6,ipv4_src=t.dst,ipv4_dst=t.src,tcp_src=ht.dst_port,tcp_dst=ht.src_port,tcp_flags=0x012)
									match = parser.OFPMatch(eth_type=0x800,eth_dst=src, ip_proto=6,tcp_flags=0x012)
									actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
									self.add_flow(datapath, 2, match, actions)
									self.logger.info("Pridal som flow pre SYN-ACK src: %s, dst: %s:, src_port: %d, dst_port: %d, src_ip: %s, dst_ip: %s", src,dst,ht.dst_port,ht.src_port,t.dst,t.src)

									print("MP_JOIN SYN. Receiver's token: ", int(hexopt[4:][:8],16))
									print("MP_JOIN SYN. Sender's nonce: ", int(hexopt[12:],16))
								elif ht.bits == 18:         # SYN-ACK
									self.logger.info("Prisiel MP_JOIN SYN-ACK. Prisiel lebo mam pravidlo pre neho. Toto pravidlo teraz zmazem.")
							#		string = 'ovs-ofctl -OOpenFlow15 del-flows s1 "eth_dst='+dst+',tcp_flags=0x012"'
							#		os.system(string)
									print("MP_JOIN SYN-ACK. Sender's truncated HMAC :", int(hexopt[4:][:16],16))
									print("MP_JOIN SYN-ACK. Sender's nonce: ", int(hexopt[20:],16))
								elif ht.bits == 16:         # ACK
									self.logger.info("Prisiel MP_JOIN ACK. Prisiel lebo mam pravidlo pre neho. Toto pravidlo teraz zmazem.")
							#		string = 'ovs-ofctl -OOpenFlow15 del-flows s1 "eth_dst='+dst+',tcp_flags=0x010"'
							#		os.system(string)
									print("MP_JOIN ACK. Sender's HMAC :", hexopt[4:])

			if ht.src_port == 80:
				print
				'HTTP!!!'
			elif ht.dst_port == 80:
				print
				'HTTP!!!'

		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})


		# learn a mac address to avoid FLOOD next time.
		self.mac_to_port[dpid][src] = in_port


		if dst in self.mac_to_port[dpid]: #and flooduj == 0:
			out_port = self.mac_to_port[dpid][dst]
		else:
			out_port = ofproto.OFPP_FLOOD

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

		match = parser.OFPMatch(in_port=in_port)
		out = parser.OFPPacketOut(datapath, msg.buffer_id,
								  match, actions, data)
		datapath.send_msg(out)

		#self.logger.info("Aktualne flowy: ")
		#self.logger.info(commands.getstatusoutput('ovs-ofctl -OOpenFlow15 dump-flows s1'))
