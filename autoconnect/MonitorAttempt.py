from ConnectionAttempt import ConnectionAttempt
from RARPTable import *
from scapy.all import *
from ipaddress import *


class MonitorAttempt(ConnectionAttempt):

    def __init__(self, interface):
        ConnectionAttempt.__init__(self, interface)
        self.rarp_table = RARPTable()
        self.packets = None
        self.gateway_ip = None
        self.gateway_mac = None
        self.acc_and = 0xffffffff
        self.acc_or = 0x00000000
        self.network = None
        self.ip = None
        self.ignore_ip = {'0.0.0.0', '192.168.1.1', '192.168.1.49', '160.97.146.123', '160.97.144.1', '160.97.147.90',
                         '160.97.144.3', '160.97.146.99', '160.97.145.57', '160.97.145.18', '160.97.146.217',
                         '160.97.147.0', '160.97.146.19', '160.97.144.2', '160.97.146.1', '160.97.145.172',
                         '160.97.144.32', '160.97.144.224', '160.97.147.136', '160.97.146.205'}

    def connect(self):
        self.sniff()
        # self.rarp_table.print()
        self.find_gateway()
        self.network_discover()
        print("Default gateway: " + str(self.gateway_ip))
        print("Network: " + str(self.network))
        self.find_ip()
        print("IP address: " + str(self.ip))

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

        net_address = self.acc_and & self.acc_or
        subnet_mask = self.acc_and ^ self.acc_or
        subnet_mask = 0xffffffff - subnet_mask

        net_address_str = str(IPv4Address(net_address))
        net_address_str += "/" + str(IPv4Address(subnet_mask))

        self.network = IPv4Network(net_address_str)

    def add_ip(self, ip_addr):
        ip = int(IPv4Address(ip_addr))
        self.acc_and &= ip
        self.acc_or |= ip

    def find_gateway(self):
        max_count = 0
        max_mac = None
        for mac in self.rarp_table.table:
            size = len(self.rarp_table.table[mac])
            if size >= max_count:
                max_count = size
                max_mac = mac
        if max_mac is not None:
            self.set_gateway(max_mac)
            self.gateway_mac = max_mac

    def set_gateway(self, max_mac):
        for entry in self.rarp_table.table[max_mac]:
            if entry.in_arp:
                self.gateway_ip = IPv4Address(entry.ip_address)
                return

    def find_ip(self):
        free_ip = None
        hosts = list(self.network.hosts())
        tmp_ip = hosts[random.randint(0, len(hosts))]
        print(tmp_ip)
        for ip in hosts:
            ip_dst = str(ip)
            print(ip_dst)
            arp_request = self.make_arp_request(tmp_ip, ip_dst)
            arp_reply = srp1(arp_request, timeout=3, verbose=0)
            if arp_reply is not None:
                print(arp_reply.display())
            else:
                free_ip = ip
                break
        self.ip = free_ip

    def make_arp_request(self, ip_src, ip_dst):
        ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac_address)
        arp = ARP(op=1, hwsrc=self.mac_address, psrc=ip_src,
                  hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_dst)
        pkt = ether / arp
        return pkt

    def sniff(self):
        # self.packets = sniff(filter="arp || tcp", prn=self.pkt_process,
        #                 offline="/home/nigre/Documents/Thesis/wiresharkcap-root.pcapng")
        packets = sniff(filter="arp || tcp", prn=self.pkt_process, count=100)

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
        ip_src = pkt[IP].src
        mac_src = pkt[Ether].src
        self.rarp_table.add_entry(mac_src, ip_src, False)
        ip_dst = pkt[IP].dst
        mac_dst = pkt[Ether].dst
        self.rarp_table.add_entry(mac_dst, ip_dst, False)
