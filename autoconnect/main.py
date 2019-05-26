from DHCPAttempt import DHCPAttempt
from GuessAttempt import GuessAttempt
from MonitorAttempt import MonitorAttempt
from scapy.arch.linux import get_if_list


# dhcpAttempt = DHCPAttempt('wlp2s0')
# dhcpAttempt.connect()

# guessAttempt = GuessAttempt('wlp2s0')
# guessAttempt.connect()

monitorAttempt = MonitorAttempt('wlp2s0')
monitorAttempt.connect()
