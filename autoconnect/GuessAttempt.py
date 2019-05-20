from scapy.all import *
from ConnectionAttempt import ConnectionAttempt
from ARPTable import *


class GuessAttempt(ConnectionAttempt):

    def __init__(self, interface):
        ConnectionAttempt.__init__(self, interface)
        self.arpTable = ARPTable()

    def connect(self):
        self.sniff()
        # for entry in self.arpTable.table:
        #     print(self.arpTable.table[entry].ipaddress + "\t" + self.arpTable.table[entry].macaddress + "\t" +
        #           str(self.arpTable.table[entry].count))

    def sniff(self):
        packets = sniff(filter="arp", prn = self.arpProcess,
                        offline="/home/nigre/Documents/Thesis/wiresharkcap-root.pcapng")

    def arpProcess(selft, pkt):
        selft.arpTable.addOrUpdateEntry(pkt[ARP].psrc, pkt[ARP].hwsrc)
        selft.arpTable.addOrUpdateEntry(pkt[ARP].pdst, pkt[ARP].hwdst)
        # TODO Network Discover function