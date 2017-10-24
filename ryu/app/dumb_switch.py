from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4


class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst_mac = eth.dst
        src_mac = eth.src

        self.logger.info("taketo protokoly su:")

        t = pkt.get_protocol(ipv4.ipv4)

        if t:
            print 'zdrojova ip: ',t.src
            print 'dest ip: ',t.dst

        ht = pkt.get_protocol(tcp.tcp)

        if ht:
            print 'zdrojovy port: ',ht.src_port
            print 'destination port: ',ht.dst_port

            options = ht.option

            join = 0
            if options:
                if len(options) > 0:
                    for opt in options:
                        print opt.kind
                        if opt.kind == 30:
                            print 'mp_capable'
            if ht.src_port == 80:
                print 'HTTP!!!'
            elif ht.dst_port == 80:
                print 'HTTP!!!'
        join = 0
        self.logger.info("prisiel packet so source mac: %s a dest mac: %s",src_mac,dst_mac)
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        dp.send_msg(out)

