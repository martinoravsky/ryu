#!/usr/bin/python

from subprocess import call
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():
	net = Mininet(topo=None, build=False, link=TCLink)

	info('*** Adding controller\n')
	c0 = net.addController(name='c0',
						   controller=RemoteController,
						   protocol='tcp',
						   ip='127.0.0.1',
						   port=6633)

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
	s12 = net.addSwitch('s12', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s13 = net.addSwitch('s13', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s14 = net.addSwitch('s14', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s16 = net.addSwitch('s16', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s17 = net.addSwitch('s17', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s18 = net.addSwitch('s18', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s19 = net.addSwitch('s19', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s20 = net.addSwitch('s20', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s21 = net.addSwitch('s21', cls=OVSKernelSwitch, protocols='OpenFlow13')
	net.addLink(s1, s2, bw=100)
	net.addLink(s2, s3, bw=100)
	net.addLink(s3, s4, bw=100)
	net.addLink(s4, s1, bw=100)
	net.addLink(s5, s6, bw=100)
	net.addLink(s6, s7, bw=100)
	net.addLink(s5, s8, bw=100)
	net.addLink(s8, s7, bw=100)
	net.addLink(s9, s10, bw=100)
	net.addLink(s10, s11, bw=100)
	net.addLink(s9, s12, bw=100)
	net.addLink(s12, s11, bw=100)
	net.addLink(s13, s14, bw=100)
	net.addLink(s16, s13, bw=100)
	net.addLink(s1, s17, bw=100)
	net.addLink(s20, s3, bw=100)
	net.addLink(s5, s18, bw=100)
	net.addLink(s7, s20, bw=100)
	net.addLink(s9, s19, bw=100)
	net.addLink(s9, s20, bw=100)
	net.addLink(s13, s20, bw=100)
	net.addLink(s5, s19, bw=100)
	net.addLink(s21, s14, bw=100)
	net.addLink(s21, s16, bw=100)
	net.addLink(s3, s19, bw=100)
	net.addLink(s11, s18, bw=100)
	net.addLink(s1, s18, bw=100)
	net.addLink(s7, s17, bw=100)
	net.addLink(s11, s17, bw=100)
	net.addLink(s13, s17, bw=100)
	net.addLink(s21, s18, bw=100)
	net.addLink(s21, s19, bw=100)

	info('*** Starting network\n')
	net.build()
	info('*** Starting controllers\n')
	for controller in net.controllers:
		controller.start()

	info('*** Starting switches\n')
	net.get('s12').start([c0])
	net.get('s21').start([c0])
	net.get('s20').start([c0])
	net.get('s14').start([c0])
	net.get('s16').start([c0])
	net.get('s11').start([c0])
	net.get('s9').start([c0])
	net.get('s5').start([c0])
	net.get('s13').start([c0])
	net.get('s7').start([c0])
	net.get('s17').start([c0])
	net.get('s6').start([c0])
	net.get('s18').start([c0])
	net.get('s3').start([c0])
	net.get('s2').start([c0])
	net.get('s8').start([c0])
	net.get('s4').start([c0])
	net.get('s1').start([c0])
	net.get('s10').start([c0])
	net.get('s19').start([c0])

	info('*** Post configure switches and hosts\n')

	info('*** Add interfaces to switch ***')

	_intf = Intf('eth0', node=s2)
	_intf = Intf('eth1', node=s4)
	_intf = Intf('eth2', node=s14)
	_intf = Intf('eth3', node=s16)

	call(['ovs-vsctl', 'add-port', 's2', 'eth0'])
	call(['ovs-vsctl', 'add-port', 's4', 'eth1'])
	call(['ovs-vsctl', 'add-port', 's14', 'eth2'])
	call(['ovs-vsctl', 'add-port', 's16', 'eth3'])
	CLI(net)
	net.stop()

if __name__ == '__main__':
	setLogLevel('info')
	myNetwork()
