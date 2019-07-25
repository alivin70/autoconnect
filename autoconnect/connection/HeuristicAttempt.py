from abc import abstractmethod
from connection.ConnectionAttempt import ConnectionAttempt
from ipaddress import *
from scapy.all import *
from scapy.layers.inet import Ether
from scapy.layers.l2 import ARP
from util.Interface import *


class HeuristicAttempt (ConnectionAttempt):

    def __init__(self, interface):
        ConnectionAttempt.__init__(self, interface)
        self.acc_and = 0xffffffff
        self.acc_or = 0x00000000
        self.network = None
        self.gateway = None
        self.ip = None
        self.ignore_ip = {'0.0.0.0'}

    def find_network(self):
        # TODO Fix subnet_mask in case of ones after the first zero.
        net_address = self.acc_and & self.acc_or
        subnet_mask = self.acc_and ^ self.acc_or
        subnet_mask = 0xffffffff - subnet_mask

        net_address_str = str(IPv4Address(net_address))
        net_address_str += "/" + str(IPv4Address(subnet_mask))

        return net_address_str

    @abstractmethod
    def find_gateway(self):
        pass

    @abstractmethod
    def find_ip(self):
        pass

    def add_ip(self, ip_addr):
        # arp_reply = self.check_ip(ip_addr)
        # if arp_reply:
        #     print("Adding IP: " + ip_addr)
        ip = int(IPv4Address(ip_addr))
        self.acc_and &= ip
        self.acc_or |= ip
        print(str(IPv4Address(self.acc_and)) + "\t" + str(IPv4Address(self.acc_or)) + "\n", end='')

    def check_ip(self, ip_addr):
        # TODO check ip with arp-request (to avoid processing IP of a different subnet)
        tmp_ip = "0.0.0.0"
        print("Sending arp request for IP: " + str(ip_addr))
        arp_request = self.make_arp_request(tmp_ip, ip_addr)
        arp_reply = srp1(arp_request, timeout=3, verbose=0)
        if arp_reply is not None:
            print(arp_reply.display())
        return arp_reply is not None

    def make_arp_request(self, ip_src, ip_dst):
        ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac_address)
        arp = ARP(op=1, hwsrc=self.mac_address, psrc=ip_src,
                  hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_dst)
        pkt = ether / arp
        return pkt

    @abstractmethod
    def connect(self):
        pass

    def configure_network(self):
        if self.network is not None and self.gateway is not None and self.ip is not None:
            setup_interface(self.interface, str(self.ip), str(self.network.netmask))
            setup_default_gateway(str(self.gateway))
            setup_dns(str(self.gateway) + ",8.8.8.8")
            return True
        else:
            return False
