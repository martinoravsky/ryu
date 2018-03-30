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

	net = Mininet( topo=None, build=False, link=TCLink)

	info( '*** Adding controller\n' )
	c0=net.addController(name='c0',
					  controller=RemoteController,
					  protocol='tcp',
			  ip='127.0.0.1',
					  port=6633)

	info( '*** Add switches\n')
	s1 = net.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s2 = net.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s3 = net.addSwitch('s3', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s4 = net.addSwitch('s4', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s5 = net.addSwitch('s5', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s6 = net.addSwitch('s6', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s7 = net.addSwitch('s7', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s8 = net.addSwitch('s8', cls=OVSKernelSwitch, protocols='OpenFlow13')
	s9 = net.addSwitch('s9', cls=OVSKernelSwitch, protocols='OpenFlow13')
	net.addLink('s1', 's2', bw=10)
	net.addLink('s1', 's3', bw=10)
	net.addLink('s2', 's7', bw=10)
	net.addLink('s7', 's8', bw=10)
	net.addLink('s8', 's9', bw=10)
	net.addLink('s9', 's6', bw=10)
	net.addLink('s3', 's4', bw=10)
	net.addLink('s4', 's5', bw=10)
	net.addLink('s5', 's6', bw=10)
	net.addLink('s3', 's6', bw=10)

	info( '*** Starting network\n')
	net.build()
	info( '*** Starting controllers\n')
	for controller in net.controllers:
		controller.start()

	info( '*** Starting switches\n')
	net.get('s1').start([c0])
	net.get('s2').start([c0])
	net.get('s3').start([c0])
	net.get('s4').start([c0])
	net.get('s5').start([c0])
	net.get('s6').start([c0])
	net.get('s7').start([c0])
	net.get('s8').start([c0])
	net.get('s9').start([c0])


	info( '*** Post configure switches and hosts\n')

	info( '*** Add interfaces to switch ***' )
	
	_intf = Intf( 'eth0', node=s1 )
	_intf = Intf( 'eth1', node=s2 )
	_intf = Intf( 'eth2', node=s6 )
	_intf = Intf( 'eth3', node=s9 )

	call(['ovs-vsctl','add-port','s1','eth0'])
	call(['ovs-vsctl','add-port','s2','eth1'])
	call(['ovs-vsctl','add-port','s6','eth2'])
	call(['ovs-vsctl','add-port','s9','eth3'])
	CLI(net)
	net.stop()

if __name__ == '__main__':
	setLogLevel( 'info' )
	myNetwork()

