from scapy.all import *
from connection.ConnectionAttempt import ConnectionAttempt
from util.ARPTable import *
from ipaddress import *


class GuessAttempt(ConnectionAttempt):

    def __init__(self, interface):
        ConnectionAttempt.__init__(self, interface)
        self.arp_table = ARPTable()
        self.acc_and = 0xffffffff
        self.acc_or = 0x00000000
        self.network = None
        self.gateway = None
        self.ip = None
        self.count = 0
        self.ignore_ip = {'0.0.0.0'}

    def connect(self):
        self.sniff()
        self.network = IPv4Network(self.network)
        self.gateway = IPv4Address(self.gateway)
        print("Network: " + str(self.network))
        print("Default gateway: " + str(self.gateway))
        self.find_ip()
        print("IP address: " + str(self.ip))

    def network_discover(self):
        # TODO Fix subnet_mask in case of ones after the first zero.
        net_address = self.acc_and & self.acc_or
        subnet_mask = self.acc_and ^ self.acc_or
        subnet_mask = 0xffffffff - subnet_mask

        net_address_str = str(IPv4Address(net_address))
        net_address_str += "/" + str(IPv4Address(subnet_mask))

        network = net_address_str
        return network

    def find_gateway(self):
        max_count = 0
        gateway = None
        for entry in self.arp_table.table:
            if self.arp_table.table[entry].count > max_count:
                max_count = self.arp_table.table[entry].count
                gateway = self.arp_table.table[entry].ip_address

        return gateway

    def find_ip(self):
        hosts = list(self.network.hosts())
        tmp_ip = hosts[random.randint(0, len(hosts))]
        print("Tmp IP address to find a free IP: " + str(tmp_ip))
        for ip in hosts:
            if not self.arp_table.contains(str(ip)):
                ip_dst = str(ip)
                print("Sending arp request for IP: " + str(ip_dst))
                arp_request = self.make_arp_request(tmp_ip, ip_dst)
                arp_reply = srp1(arp_request, timeout=3, verbose=0)
                if arp_reply is not None:
                    print(arp_reply.display())
                else:
                    self.ip = ip
                    return

    def make_arp_request(self, ip_src, ip_dst):
        ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac_address)
        arp = ARP(op=1, hwsrc=self.mac_address, psrc=ip_src,
                  hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_dst)
        pkt = ether / arp
        return pkt

    def stopfilter(self, x):
        network = self.network_discover()
        gateway = self.find_gateway()
        if network != self.network or gateway != self.gateway:
            self.network = network
            self.gateway = gateway
            self.count = 1
        else:
            self.count += 1

        if self.count == 20:
            return True
        else:
            return False

    def sniff(self):
        packets = sniff(filter="arp", prn=self.arp_process, stop_filter=self.stopfilter)

    def add_ip(self, ip_addr):
        ip = int(IPv4Address(ip_addr))
        self.acc_and &= ip
        self.acc_or |= ip

    def arp_process(self, pkt):
        # TODO check ip with arp-request (to avoid processing IP of a different subnet)
        ip_src = pkt[ARP].psrc
        mac_src = pkt[ARP].hwsrc
        if ip_src not in self.ignore_ip:
            self.arp_table.add_or_update_entry(ip_src, mac_src)
            self.add_ip(ip_src)
        ip_dst = pkt[ARP].pdst
        mac_dst = pkt[ARP].hwdst
        if ip_dst not in self.ignore_ip:
            self.arp_table.add_or_update_entry(ip_dst, mac_dst)
            self.add_ip(ip_dst)
