from ConnectionAttempt import ConnectionAttempt
from Interface import *
from scapy.all import *


class DHCPAttempt(ConnectionAttempt):

    def __init__(self, interface):
        ConnectionAttempt.__init__(self, interface)
        conf.checkIPaddr = False

    def make_dhcp_discover(self):
        ethernet = Ether(src=self.mac_address, dst='ff:ff:ff:ff:ff:ff')
        ip = IP(src='0.0.0.0', dst='255.255.255.255')
        udp = UDP(dport=67, sport=68)
        bootp = BOOTP(chaddr=self.mac_address_raw, xid=RandInt())
        dhcp = DHCP(options=[('message-type', 'discover'), ("hostname", self.hostname), 'end'])
        dhcp_discover_pkt = ethernet / ip / udp / bootp / dhcp
        return dhcp_discover_pkt

    def make_dhcp_request(self, my_ip_address, server_id, xid):
        ethernet = Ether(src=self.mac_address, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=self.mac_address_raw, xid=xid)
        dhcp = DHCP(options=[("message-type", "request"), ("server_id", server_id),
                             ("requested_addr", my_ip_address), ("hostname", self.hostname), "end"])

        dhcp_request = ethernet / ip / udp / bootp / dhcp
        return dhcp_request

    # Function to extract dhcp_options by key
    def get_dhcp_option(self, dhcp_options, key):
        must_decode = ['hostname', 'domain', 'vendor_class_id']
        try:
            for i in dhcp_options:
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
        dhcp_discover_pkt = self.make_dhcp_discover()
        print("Send DHCP Discover")
        dhcp_offer = srp1(dhcp_discover_pkt, iface=self.interface, verbose=0)
        my_ip_address = dhcp_offer[BOOTP].yiaddr
        server_id = self.get_dhcp_option(dhcp_offer[DHCP].options, 'server_id')
        xid = dhcp_offer[BOOTP].xid
        print("Received DHCP Offer: IP = %s" % (my_ip_address))
        dhcp_request = self.make_dhcp_request(my_ip_address, server_id, xid)
        print("Send DHCP Request")
        dhcp_ack = srp1(dhcp_request, iface=self.interface, verbose=0)
        if(dhcp_ack != None):
            print("Received DHCP ACK")
            dhcp_options = dhcp_ack[DHCP].options
            subnet_mask = self.get_dhcp_option(dhcp_options, 'subnet_mask')
            broadcast_address = self.get_dhcp_option(dhcp_options, 'broadcast_address')
            router = self.get_dhcp_option(dhcp_options, 'router')
            dns_server = self.get_dhcp_option(dhcp_options, 'name_server')
            print(subnet_mask, broadcast_address, router, dns_server)
            # setup_interface(self.interface, my_ip_address, subnet_mask)
            # setup_default_gateway(router)
            # setup_dns(dns_server)