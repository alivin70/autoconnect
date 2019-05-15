from autoconnect.ConnectionAttempt import ConnectionAttempt
from scapy.all import *


class DHCPAttempt(ConnectionAttempt):

    def __init__(self):
        pass

    def connect(self):
        localiface = 'lo'
        myhostname = 'autoconnect'
        localmac = get_if_hwaddr(localiface)
        print(localmac)

        # make DHCP DISCOVER
        dhcp_discover = Ether(src=localmac, dst='ff:ff:ff:ff:ff:ff') / IP(src='0.0.0.0', dst='255.255.255.255') / UDP(
            dport=67, sport=68) / BOOTP(chaddr=localmac, xid=RandInt()) / DHCP(
            options=[('message-type', 'discover'), 'end'])
        print(dhcp_discover.display())
        dhcp_offer = srp1(dhcp_discover, iface=localiface)