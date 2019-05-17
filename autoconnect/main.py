from DHCPAttempt import DHCPAttempt
from scapy.arch.linux import get_if_list


# print(get_if_list())

dhcpAttempt = DHCPAttempt('wlp2s0')

dhcpAttempt.connect()