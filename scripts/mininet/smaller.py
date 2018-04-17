#!/usr/bin/python

from subprocess import call
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call


def myNetwork():
	net = Mininet(topo=None, build=False, link=TCLink)

	info('*** Adding controller\n')
	c0 = net.addController(name='c0', controller=RemoteController, protocol='tcp', ip='127.0.0.1', port=6633)

	info('*** Add switches\n')
	s1 = net.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s2 = net.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s3 = net.addSwitch('s3', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s4 = net.addSwitch('s4', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s5 = net.addSwitch('s5', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s6 = net.addSwitch('s6', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s7 = net.addSwitch('s7', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s8 = net.addSwitch('s8', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s9 = net.addSwitch('s9', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s10 = net.addSwitch('s10', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s11 = net.addSwitch('s11', cls=OVSKernelSwitch, protocols='OpenFlow13')
	net.addLink('s1', 's2', bw=10)
	net.addLink('s1', 's3', bw=10)
	net.addLink('s3', 's4', bw=10)
	net.addLink('s2', 's5', bw=10)
	net.addLink('s4', 's5', bw=10)
	net.addLink('s3', 's7', bw=10)
	net.addLink('s4', 's8', bw=10)
	net.addLink('s7', 's8', bw=10)
	net.addLink('s6', 's7', bw=10)
	net.addLink('s8', 's9', bw=10)
	net.addLink('s9', 's11', bw=10)
	net.addLink('s6', 's9', bw=10)
	net.addLink('s6', 's10', bw=10)
	net.addLink('s10', 's9', bw=10)

	info('*** Adding end devices.\n')
	h1 = net.addHost('h1', ip='10.0.0.1')
	TCLink(h1, s1, intfName='h1-eth0')
	TCLink(h1, s6, intfName='h1-eth1')
	h1.setIP('10.0.0.1', intf='h1-eth0')
	h1.setIP('10.0.0.2', intf='h1-eth1')
	h1.setMAC('00:00:00:00:00:01', intf='h1-eth0')
	h1.setMAC('00:00:00:00:00:02', intf='h1-eth1')
	h1.cmd('ip rule add from 10.0.0.1 table 1')
	h1.cmd('ip rule add from 10.0.0.2 table 2')
	h1.cmd('ip route add 10.0.0.0/24 dev h1-eth0 scope link table 1')
	h1.cmd('ip route add 10.0.0.0/24 dev h1-eth1 scope link table 2')
	h1.cmd('sysctl -w net.ipv4.conf.all.arp_filter=1')
	h1.cmd('/home/mato/ryu/scripts/h1_arp.sh')

	h2 = net.addHost('h2', ip='10.0.0.3')
	TCLink(h2, s5, intfName='h2-eth0')
	TCLink(h2, s11, intfName='h2-eth1')
	h2.setIP('10.0.0.3', intf='h2-eth0')
	h2.setIP('10.0.0.4', intf='h2-eth1')
	h2.setMAC('00:00:00:00:00:03', intf='h2-eth0')
	h2.setMAC('00:00:00:00:00:04', intf='h2-eth1')
	h2.cmd('ip rule add from 10.0.0.3 table 1')
	h2.cmd('ip rule add from 10.0.0.4 table 2')
	h2.cmd('ip route add 10.0.0.0/24 dev h2-eth0 scope link table 1')
	h2.cmd('ip route add 10.0.0.0/24 dev h2-eth1 scope link table 2')
	h2.cmd('sysctl -w net.ipv4.conf.all.arp_filter=1')
	h2.cmd('/home/mato/ryu/scripts/h2_arp.sh')


	info('*** Starting network\n')
	net.build()
	info('*** Starting controllers\n')
	for controller in net.controllers:
		controller.start()

	info('*** Starting switches\n')
	net.get('s1').start([c0])
	net.get('s2').start([c0])
	net.get('s3').start([c0])
	net.get('s4').start([c0])
	net.get('s5').start([c0])
	net.get('s6').start([c0])
	net.get('s7').start([c0])
	net.get('s8').start([c0])
	net.get('s9').start([c0])
	net.get('s10').start([c0])
	net.get('s11').start([c0])

	info('*** Post configure switches and hosts\n')

	info('*** Add interfaces to switch ***')

	#_intf = Intf('eth0', node=s1)
	#_intf = Intf('eth1', node=s6)
	#_intf = Intf('eth2', node=s5)
	#_intf = Intf('eth3', node=s11)

	#call(['ovs-vsctl', 'add-port', 's1', 'eth0'])
	#call(['ovs-vsctl', 'add-port', 's6', 'eth1'])
	#call(['ovs-vsctl', 'add-port', 's5', 'eth2'])
	#call(['ovs-vsctl', 'add-port', 's11', 'eth3'])
	info('*** Starting iperf server on host #2')
	h2.cmd('iperf -s &')
	info('*** Done.\n')

	CLI(net)
	net.stop()


if __name__ == '__main__':
	setLogLevel('info')
	myNetwork()

