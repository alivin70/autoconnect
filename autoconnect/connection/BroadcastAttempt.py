from scapy.all import *
from connection.HeuristicAttempt import HeuristicAttempt
from util.ARPTable import *
from ipaddress import *
from scapy.layers.l2 import ARP


class BroadcastAttempt(HeuristicAttempt):

    def __init__(self, interface):
        HeuristicAttempt.__init__(self, interface)
        self.arp_table = ARPTable()
        self.count = 0

    def connect(self):
        self.sniff()
        self.arp_table.print()
        self.network = IPv4Network(self.network)
        self.gateway = IPv4Address(self.gateway)
        print("Network: " + str(self.network))
        print("Default gateway: " + str(self.gateway))
        self.ip = IPv4Address(self.find_ip())
        print("IP address: " + str(self.ip))

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
        print("Tmp IP address used to find a free IP: " + str(tmp_ip))
        for ip in hosts:
            if not self.arp_table.contains(str(ip)):
                ip_dst = str(ip)
                print("Sending arp request for IP: " + str(ip_dst))
                arp_request = self.make_arp_request(tmp_ip, ip_dst)
                arp_reply = srp1(arp_request, timeout=3, verbose=0)
                if arp_reply is not None:
                    print(arp_reply.display())
                else:
                    return ip

    def stop_filter(self, x):
        network = self.find_network()
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
        sniff(filter="arp", prn=self.arp_process, stop_filter=self.stop_filter)

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
