


ethtool -K ens4f0 rxhash on
sleep 3
ethtool -K ens4f0 rxhash off

#
lxc exec ctrlcontainer -- bash /home/ubuntu/setup_interface.sh

# configure NAT pin holes between container and host for pon
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.39.117.170:80
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 10.39.117.170:443
iptables -A FORWARD -p tcp -d 10.39.117.170 --dport 80 -j ACCEPT
iptables -A FORWARD -p tcp -d 10.39.117.170 --dport 443 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.39.117.170:80
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 10.39.117.170:443
iptables -A FORWARD -p tcp -d 10.39.117.170 --dport 80 -j ACCEPT
iptables -A FORWARD -p tcp -d 10.39.117.170 --dport 443 -j ACCEPT

