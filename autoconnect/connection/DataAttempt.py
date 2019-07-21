from connection.HeuristicAttempt import HeuristicAttempt
from util.RARPTable import *
from scapy.all import *
from ipaddress import *
from scapy.layers.inet import IP, TCP, Ether
from scapy.layers.l2 import ARP


class DataAttempt(HeuristicAttempt):

    def __init__(self, interface):
        HeuristicAttempt.__init__(self, interface)
        self.rarp_table = RARPTable()
        self.packets = None
        self.gateway_mac = None

    def connect(self):
        self.sniff()
        self.rarp_table.print()
        self.gateway = IPv4Address(self.find_gateway())
        self.network = IPv4Network(self.network_discover())
        print("Network: " + str(self.network))
        print("Default gateway: " + str(self.gateway))
        self.ip = IPv4Address(self.find_ip())
        print("IP address: " + str(self.ip))

    def find_gateway(self):
        max_count = 0
        max_mac = None
        for mac in self.rarp_table.table:
            size = len(self.rarp_table.table[mac])
            if size >= max_count:
                max_count = size
                max_mac = mac
        if max_mac is not None:
            self.gateway_mac = max_mac
            return self.find_gateway_ip(max_mac)

    def find_ip(self):
        hosts = list(self.network.hosts())
        tmp_ip = hosts[random.randint(0, len(hosts))]
        print("Tmp IP address used to find a free IP: " + str(tmp_ip))
        for ip in hosts:
            ip_dst = str(ip)
            print("Sending arp request for IP: " + str(ip_dst))
            arp_request = self.make_arp_request(tmp_ip, ip_dst)
            arp_reply = srp1(arp_request, timeout=3, verbose=0)
            if arp_reply is not None:
                print(arp_reply.display())
            else:
                return ip

    def network_discover(self):
        for pkt in self.packets:
            if ARP in pkt:
                ip_src = pkt[ARP].psrc
                if ip_src not in self.ignore_ip:
                    self.add_ip(ip_src)
                ip_dst = pkt[ARP].pdst
                if ip_dst not in self.ignore_ip:
                    self.add_ip(ip_dst)
            elif TCP in pkt:
                mac_src = pkt[Ether].src
                mac_dst = pkt[Ether].dst
                if mac_src == self.gateway_mac:
                    ip_dst = pkt[IP].dst
                    self.add_ip(ip_dst)
                elif mac_dst == self.gateway_mac:
                    ip_src = pkt[IP].src
                    self.add_ip(ip_src)

        return self.find_network()

    def find_gateway_ip(self, max_mac):
        for entry in self.rarp_table.table[max_mac]:
            if entry.in_arp:
                return entry.ip_address

    def sniff(self):
        # self.packets = sniff(filter="arp || tcp", prn=self.pkt_process, offline="/home/nigre/Documents/Thesis/wiresharkcap-root.pcapng")
        self.packets = sniff(filter="arp || tcp", prn=self.pkt_process, count=100)

    def pkt_process(self, pkt):
        if ARP in pkt:
            self.arp_process(pkt)
        elif TCP in pkt:
            self.tcp_process(pkt)

    def arp_process(self, pkt):
        ip_src = pkt[ARP].psrc
        mac_src = pkt[ARP].hwsrc
        if ip_src not in self.ignore_ip:
            self.rarp_table.add_or_update_entry(mac_src, ip_src, True)
        ip_dst = pkt[ARP].pdst
        mac_dst = pkt[ARP].hwdst
        if ip_dst not in self.ignore_ip:
            self.rarp_table.add_or_update_entry(mac_dst, ip_dst, True)

    def tcp_process(self, pkt):
        ip_src = pkt[IP].src
        mac_src = pkt[Ether].src
        self.rarp_table.add_or_update_entry(mac_src, ip_src, False)
        ip_dst = pkt[IP].dst
        mac_dst = pkt[Ether].dst
        self.rarp_table.add_or_update_entry(mac_dst, ip_dst, False)
