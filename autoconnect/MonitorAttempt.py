from ConnectionAttempt import ConnectionAttempt
from RARPTable import *
from scapy.all import *


class MonitorAttempt(ConnectionAttempt):

    def __init__(self, interface):
        ConnectionAttempt.__init__(self, interface)
        self.rarp_table = RARPTable()

    def connect(self):
        self.sniff()
        for ip in self.rarp_table.table:
            print(ip + "    ->      ", end='')
            for entry in self.rarp_table.table[ip]:
                print(entry.ip_address, entry.in_arp)

    def sniff(self):
        packets = sniff(filter="arp", prn = self.pkt_process,
                        offline="/home/nigre/Documents/Thesis/wiresharkcap-root.pcapng")

    def pkt_process(self, pkt):
        if ARP in pkt:
            self.arp_process(pkt)
        elif TCP in pkt:
            self.tcp_process(pkt)

    def arp_process(self, pkt):
        ip_src = pkt[ARP].psrc
        mac_src = pkt[ARP].hwsrc
        if ip_src != '0.0.0.0':
            self.rarp_table.add_entry(mac_src, ip_src, True)
        ip_dst = pkt[ARP].pdst
        mac_dst = pkt[ARP].hwdst
        if mac_dst != '00:00:00:00:00:00':
            self.rarp_table.add_entry(mac_dst, ip_dst, True)

    def tcp_process(self, pkt):
        pass