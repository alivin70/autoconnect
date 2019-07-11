from requests import *
from captiveportal.NodogsplashCaptivePortal import NodogsplashCaptivePortal

# dhcpAttempt = DHCPAttempt('wlp2s0')
# dhcpAttempt.connect()

# guessAttempt = GuessAttempt('wlp2s0')
# guessAttempt.connect()

# mirrorAttempt = MirrorAttempt('wlp2s0')
# mirrorAttempt.connect()

# TODO Check for connection (if I can reach the gateway)

resp = request(method='GET', url="http://clients3.google.com/generate_204", allow_redirects=False)
print(resp.status_code)
print(resp.history)
print(resp.url)

if resp.is_redirect:
    # zscp = ZeroShellCaptivePortal()
    # zscp.try_to_connect()
    # wdcp = WifiDogCaptivePortal()
    # wdcp.try_to_connect()
    ndscp = NodogsplashCaptivePortal()
    ndscp.try_to_connect()

else:
    print("Successfully connected!")