from ConnectionAttempt import ConnectionAttempt
from scapy.all import *


class DHCPAttempt(ConnectionAttempt):

    def __init__(self, interface):
        ConnectionAttempt.__init__(self, interface)
        conf.checkIPaddr = False

    def makeDhcpDiscover(self):
        ethernet = Ether(src=self.macaddress, dst='ff:ff:ff:ff:ff:ff')
        ip = IP(src='0.0.0.0', dst='255.255.255.255')
        udp = UDP(dport=67, sport=68)
        bootp = BOOTP(chaddr=self.macaddressraw, xid=RandInt())
        dhcp = DHCP(options=[('message-type', 'discover'), 'end'])
        dhcpDiscoverPkt = ethernet / ip / udp / bootp / dhcp
        return dhcpDiscoverPkt

    def makeDhcpRequest(self, myIpAddress, sourceIpAddress, xid):
        ethernet = Ether(src=self.macaddress, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=self.macaddressraw, xid=xid)
        dhcp = DHCP(options=[("message-type", "request"), ("server_id", sourceIpAddress),
                             ("requested_addr", myIpAddress), ("hostname", self.hostname), "end"])

        dhcpRequest = ethernet / ip / udp / bootp / dhcp
        return dhcpRequest

    def connect(self):
        dhcpDiscoverPkt = self.makeDhcpDiscover()
        dhcpOffer = srp1(dhcpDiscoverPkt, iface=self.interface)
        myIpAddress = dhcpOffer[BOOTP].yiaddr
        sourceIpAddress = dhcpOffer[BOOTP].siaddr
        xid = dhcpOffer[BOOTP].xid
        dhcpRequest = self.makeDhcpRequest(myIpAddress, sourceIpAddress, xid)
        dhcp_ack = srp1(dhcpRequest, iface=self.interface)

        #TODO retrieve all the information and set it to the interface