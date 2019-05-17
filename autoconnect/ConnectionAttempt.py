from abc import ABC, abstractmethod
from scapy.all import *


class ConnectionAttempt (ABC):

    def __init__(self, interface):
        self.hostname = 'raspberrypi'
        self.interface = interface
        self.macaddress = get_if_hwaddr(interface)
        self.fam, self.macaddressraw = get_if_raw_hwaddr(interface)

    @abstractmethod
    def connect(self):
        pass