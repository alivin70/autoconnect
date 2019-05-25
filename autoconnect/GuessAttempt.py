from scapy.all import *
from ConnectionAttempt import ConnectionAttempt
from ARPTable import *
from ipaddress import *


class GuessAttempt(ConnectionAttempt):

    def __init__(self, interface):
        ConnectionAttempt.__init__(self, interface)
        self.arp_table = ARPTable()
        self.acc_and = 0xffffffff
        self.acc_or = 0x00000000
        self.network = None
        self.gateway = None
        self.ignore_ip = {'0.0.0.0', '192.168.1.1', '192.168.1.49', '160.97.146.123', '160.97.144.1', '160.97.147.90',
                         '160.97.144.3', '160.97.146.99', '160.97.145.57', '160.97.145.18', '160.97.146.217',
                         '160.97.147.0', '160.97.146.19', '160.97.144.2', '160.97.146.1', '160.97.145.172',
                         '160.97.144.32', '160.97.144.224', '160.97.147.136', '160.97.146.205'}

    def connect(self):
        self.sniff()
        # for entry in self.arp_table.table:
        #     print(self.arp_table.table[entry].ip_address + "\t" + self.arp_table.table[entry].mac_address + "\t" +
        #           str(self.arp_table.table[entry].count))
        self.network_discover()
        self.find_gateway()
        print("Network: " + str(self.network))
        print("Default gateway: " + str(self.gateway))
        ip = self.find_ip()
        print("IP address: " + str(ip))

    def network_discover(self):
        # TODO Fix subnet_mask in case of ones after the first zero.
        net_address = self.acc_and & self.acc_or
        subnet_mask = self.acc_and ^ self.acc_or
        subnet_mask = 0xffffffff - subnet_mask

        net_address_str = str(IPv4Address(net_address))
        net_address_str += "/" + str(IPv4Address(subnet_mask))

        self.network = IPv4Network(net_address_str)

    def find_gateway(self):
        max_count = 0
        gateway = None
        for entry in self.arp_table.table:
            if self.arp_table.table[entry].count > max_count:
                max_count = self.arp_table.table[entry].count
                gateway = self.arp_table.table[entry].ip_address
        self.gateway = ip_address(gateway)

    def find_ip(self):
        free_ip = None
        hosts = list(self.network.hosts())
        tmp_ip = hosts[random.randint(0, len(hosts))]
        print(tmp_ip)
        for ip in hosts:
            if not self.arp_table.contains(str(ip)):
                ip_dst = str(ip)
                print(ip_dst)
                arp_request = self.make_arp_request(tmp_ip, ip_dst)
                arp_reply = srp1(arp_request, timeout=3, verbose=0)
                if arp_reply is not None:
                    print(arp_reply.display())
                else:
                    free_ip = ip
                    break
        return free_ip

    def make_arp_request(self, ip_src, ip_dst):
        ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac_address)
        arp = ARP(op=1, hwsrc=self.mac_address, psrc=ip_src,
                  hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_dst)
        pkt = ether / arp
        return pkt

    def sniff(self):
        packets = sniff(filter="arp", prn = self.arp_process,
                        offline="/home/nigre/Documents/Thesis/wiresharkcap-root.pcapng")

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
            self.add_ip(pkt[ARP].psrc)
        ip_dst = pkt[ARP].pdst
        mac_dst = pkt[ARP].hwdst
        if ip_dst not in self.ignore_ip:
            self.arp_table.add_or_update_entry(ip_dst, mac_dst)
            self.add_ip(ip_dst)
