from scapy.all import *
from ConnectionAttempt import ConnectionAttempt
from ARPTable import *
from Util import *


class GuessAttempt(ConnectionAttempt):

    def __init__(self, interface):
        ConnectionAttempt.__init__(self, interface)
        self.arp_table = ARPTable()
        self.acc_and = 0xffffffff
        self.acc_or = 0x00000000
        self.net_address = 0x00000000
        self.subnet_mask = 0x00000000
        self.ignore_ip = {'0.0.0.0', '192.168.1.1', '192.168.1.49', '160.97.146.123', '160.97.144.1', '160.97.147.90',
                         '160.97.144.3', '160.97.146.99', '160.97.145.57', '160.97.145.18', '160.97.146.217',
                         '160.97.147.0', '160.97.146.19', '160.97.144.2', '160.97.146.1', '160.97.145.172',
                         '160.97.144.32', '160.97.144.224', '160.97.147.136', '160.97.146.205'}

    def connect(self):
        self.sniff()
        # for entry in self.arp_table.table:
        #     print(self.arp_table.table[entry].ip_address + "\t" + self.arp_table.table[entry].mac_address + "\t" +
        #           str(self.arp_table.table[entry].count))
        self.infer_network()

    def infer_network(self):
        # TODO Fix subnet_mask in case of ones after the first zero.
        self.net_address = self.acc_and & self.acc_or
        print(int_to_ip(self.net_address))
        self.subnet_mask = self.acc_and ^ self.acc_or
        self.subnet_mask = 0xffffffff - self.subnet_mask
        print(int_to_ip(self.subnet_mask))


    def sniff(self):
        packets = sniff(filter="arp", prn = self.arp_process,
                        offline="/home/nigre/Documents/Thesis/wiresharkcap-root.pcapng")

    def add_ip(self, ip_address):
        ip = ip_to_int(ip_address)
        self.acc_and &= ip
        self.acc_or |= ip

    def arp_process(self, pkt):
        # TODO check ip with arp-request ???
        ip_src = pkt[ARP].psrc
        mac_src = pkt[ARP].hwsrc
        if ip_src not in self.ignore_ip:
            self.arp_table.add_or_update_entry(ip_src, mac_src)
            self.add_ip(pkt[ARP].psrc)
        ip_dst = pkt[ARP].pdst
        mac_dst = pkt[ARP].hwdst
        if ip_dst not in self.ignore_ip:
            self.arp_table.add_or_update_entry(ip_dst, mac_dst)
            self.add_ip(ip_dst)
