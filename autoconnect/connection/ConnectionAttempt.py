from abc import ABC, abstractmethod
from scapy.all import *


class ConnectionAttempt (ABC):

    def __init__(self, interface):
        self.hostname = 'raspberrypi'
        self.interface = interface
        self.mac_address = get_if_hwaddr(interface)
        self.fam, self.mac_address_raw = get_if_raw_hwaddr(interface)

    @abstractmethod
    def connect(self):
        pass

