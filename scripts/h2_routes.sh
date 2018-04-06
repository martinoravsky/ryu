ip rule add from 10.0.0.3 table 1
ip rule add from 10.0.0.4 table 2

ip route add 10.0.0.0/24 dev h2-eth0 scope link table 1
#ip route add default via 10.0.0.1 dev eth0 table 1

ip route add 10.0.0.0/24 dev h2-eth1 scope link table 2
#ip route add default via 10.0.1.1 dev eth1 table 2

