from requests import *
from scapy.arch.linux import get_if_list
from captiveportal.WifiDogCaptivePortal import WifiDogCaptivePortal
from captiveportal.NodogsplashCaptivePortal import NodogsplashCaptivePortal
from captiveportal.ZeroShellCaptivePortal import ZeroShellCaptivePortal
from connection.DHCPAttempt import DHCPAttempt
from connection.BroadcastAttempt import BroadcastAttempt
from connection.DataAttempt import DataAttempt


interfaces = get_if_list()
print("Available interfaces: ")
for i in range(0, len(interfaces)):
    print(str(i) + " - " + interfaces[i])

i = int(input("Select an interface to connect: "))
interface = None
if 0 <= i < len(interfaces):
    interface = str(interfaces[i])
else:
    exit(0)

connection_methods = [DHCPAttempt(interface), BroadcastAttempt(interface), DataAttempt(interface)]

print("Connection methods: ")
print("0 - DHCP")
print("1 - Infer from ARP traffic")
print("2 - Infer from TCP data traffic")

i = int(input("Select a connection method: "))

connected = False
if 0 <= i < len(connection_methods):
    connection_method = connection_methods[i]
    connected = connection_method.connect()
else:
    exit(0)

if connected:
    try:
        resp = request(method='GET', url="http://clients3.google.com/generate_204", allow_redirects=False)
        print(resp.status_code)
        print(resp.history)
        print(resp.url)
        if resp.is_redirect:
            print("Captive portal detected! Trying to connect . . .")
            captive_portal_handlers = {"WifiDog": WifiDogCaptivePortal(), "Nodogsplash": NodogsplashCaptivePortal(),
                                       "ZeroShell": ZeroShellCaptivePortal()}

            for item in captive_portal_handlers.keys():
                print("Trying " + item + " . . .")
                connected = captive_portal_handlers.get(item).try_to_connect()
                if connected:
                    break

        else:
            print("Successfully connected!")

    except ConnectionError:
        print("Something go wrong. The request timed out!")
else:
    print("Unable to connect!")
