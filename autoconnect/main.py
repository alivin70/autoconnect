from DHCPAttempt import DHCPAttempt
from GuessAttempt import GuessAttempt
from scapy.arch.linux import get_if_list


# dhcpAttempt = DHCPAttempt('wlp2s0')
#
# dhcpAttempt.connect()

guessAttempt = GuessAttempt('wlp2s0')
guessAttempt.connect()
