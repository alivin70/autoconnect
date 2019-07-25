from abc import ABC, abstractmethod
from scapy.all import *


class ConnectionAttempt (ABC):

    """
    A class used to represent a connection attempt

    Attributes
    ----------
    hostname : str
        the name of the host
    interface : str
        the name of the interface to connect
    mac_address : str
        the mac address of the interface to connect

    """
    def __init__(self, interface):
        self.hostname = 'raspberrypi'
        self.interface = interface
        self.mac_address = get_if_hwaddr(interface)
        self.fam, self.mac_address_raw = get_if_raw_hwaddr(interface)

    @abstractmethod
    def connect(self):
        """
        Try to discover connection settings and setup the interface

        Returns
        -------
        bool
            return True if it is able to discover and set the network, the subnet-mask, the default gateway and a free IP address
            return False otherwise

        """
        pass

