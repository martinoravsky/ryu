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

	net = Mininet( topo=None,
				   build=False,
				   ipBase='10.0.0.0/8')

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

	info( '*** Add links\n' )


	info( '*** Starting network\n')
	net.build()
	info( '*** Starting controllers\n')
	for controller in net.controllers:
		controller.start()

	info( '*** Starting switches\n')
	net.get('s1').start([c0])
	net.get('s2').start([c0])
	net.get('s3').start([c0])

	info( '*** Post configure switches and hosts\n')

	info( '*** Add interfaces to switch ***' )
	
	_intf = Intf( 'eth0', node=s1 )
	_intf = Intf( 'eth1', node=s2 )
	_intf = Intf( 'eth2', node=s3 )
	_intf = Intf( 'eth3', node=s1 )
	_intf = Intf( 'eth4', node=s2 )
	_intf = Intf( 'eth5', node=s3 )

	call(['ovs-vsctl','add-port','s1','eth0'])
	call(['ovs-vsctl','add-port','s2','eth1'])
	call(['ovs-vsctl','add-port','s3','eth2'])
	call(['ovs-vsctl','add-port','s1','eth3'])
	call(['ovs-vsctl','add-port','s2','eth4'])
	call(['ovs-vsctl','add-port','s3','eth5'])
	CLI(net)
	net.stop()

if __name__ == '__main__':
	setLogLevel( 'info' )
	myNetwork()

