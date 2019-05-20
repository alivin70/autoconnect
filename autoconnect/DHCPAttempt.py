from ConnectionAttempt import ConnectionAttempt
from Interface import *
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
        dhcp = DHCP(options=[('message-type', 'discover'), ("hostname", self.hostname), 'end'])
        dhcpDiscoverPkt = ethernet / ip / udp / bootp / dhcp
        return dhcpDiscoverPkt

    def makeDhcpRequest(self, myIpAddress, server_id, xid):
        ethernet = Ether(src=self.macaddress, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=self.macaddressraw, xid=xid)
        dhcp = DHCP(options=[("message-type", "request"), ("server_id", server_id),
                             ("requested_addr", myIpAddress), ("hostname", self.hostname), "end"])

        dhcpRequest = ethernet / ip / udp / bootp / dhcp
        return dhcpRequest

    # Function to extract dhcp_options by key
    def getDhcpOption(self, dhcpOptions, key):
        must_decode = ['hostname', 'domain', 'vendor_class_id']
        try:
            for i in dhcpOptions:
                if i[0] == key:
                    # If DHCP Server Returned multiple name servers
                    # return all as comma seperated string.
                    if key == 'name_server' and len(i) > 2:
                        return ",".join(i[1:])
                    # domain and hostname are binary strings,
                    # decode to unicode string before returning
                    elif key in must_decode:
                        return i[1].decode()
                    else:
                        return i[1]
        except:
            pass

    def connect(self):
        # TODO add and manage timeout
        dhcpDiscoverPkt = self.makeDhcpDiscover()
        print("Send DHCP Discover")
        dhcpOffer = srp1(dhcpDiscoverPkt, iface=self.interface, verbose=0)
        myIpAddress = dhcpOffer[BOOTP].yiaddr
        server_id = self.getDhcpOption(dhcpOffer[DHCP].options, 'server_id')
        xid = dhcpOffer[BOOTP].xid
        print("Received DHCP Offer: IP = %s" % (myIpAddress))
        dhcpRequest = self.makeDhcpRequest(myIpAddress, server_id, xid)
        print("Send DHCP Request")
        dhcpAck = srp1(dhcpRequest, iface=self.interface, verbose=0)
        if(dhcpAck != None):
            print("Received DHCP ACK")
            dhcpOptions = dhcpAck[DHCP].options
            subnet_mask = self.getDhcpOption(dhcpOptions, 'subnet_mask')
            broadcastAddress = self.getDhcpOption(dhcpOptions, 'broadcast_address')
            router = self.getDhcpOption(dhcpOptions, 'router')
            dnsServer = self.getDhcpOption(dhcpOptions, 'name_server')
            print(subnet_mask, broadcastAddress, router, dnsServer)
            setupInterface(self.interface, myIpAddress, subnet_mask)
            setupDefaultGateway(router)
            setupDns(dnsServer)