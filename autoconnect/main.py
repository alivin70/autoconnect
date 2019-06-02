from DHCPAttempt import DHCPAttempt
from GuessAttempt import GuessAttempt
from MonitorAttempt import MonitorAttempt
from scapy.arch.linux import get_if_list
from requests import *
from CaptivePortalHandler import CaptivePortalHandler

# dhcpAttempt = DHCPAttempt('wlp2s0')
# dhcpAttempt.connect()

# guessAttempt = GuessAttempt('wlp2s0')
# guessAttempt.connect()

# monitorAttempt = MonitorAttempt('wlp2s0')
# monitorAttempt.connect()

# TODO Check for connection

resp = request(method='GET', url="http://clients3.google.com/generate_204", allow_redirects=False)
print(resp.status_code)
print(resp.history)
print(resp.url)

if resp.is_redirect:
    cph = CaptivePortalHandler()
    cph.try_to_connect()

else:
    print("Successfully connected!")