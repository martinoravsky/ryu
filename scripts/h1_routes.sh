ip rule add from 10.0.0.1 table 1
ip rule add from 10.0.0.2 table 2

ip route add 10.0.0.0/24 dev h1-eth0 scope link table 1
#ip route add default via 10.0.0.2 dev eth0 table 1

ip route add 10.0.0.0/24 dev h1-eth1 scope link table 2
#ip route add default via 10.0.1.2 dev eth1 table 2


