from requests import *
from captiveportal.WifiDogCaptivePortal import WifiDogCaptivePortal
from captiveportal.NodogsplashCaptivePortal import NodogsplashCaptivePortal
from captiveportal.ZeroShellCaptivePortal import ZeroShellCaptivePortal

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
    print("Captive portal! Trying to connect . . .")
    captive_portal_handlers = {"WifiDog": WifiDogCaptivePortal(), "Nodogsplash": NodogsplashCaptivePortal(),
                               "ZeroShell": ZeroShellCaptivePortal()}

    for item in captive_portal_handlers.keys():
        print("Trying " + item + " . . .")
        connected = captive_portal_handlers.get(item).try_to_connect()
        if connected:
            break

else:
    print("Successfully connected!")