from requests import *
from scapy.arch.linux import get_if_list
from captiveportal.WifiDogCaptivePortal import WifiDogCaptivePortal
from captiveportal.NodogsplashCaptivePortal import NodogsplashCaptivePortal
from captiveportal.ZeroShellCaptivePortal import ZeroShellCaptivePortal
from connection.DHCPAttempt import DHCPAttempt
from connection.BroadcastAttempt import BroadcastAttempt
from connection.DataAttempt import DataAttempt
from util.Configuration import Configuration
import sys


def batch_connection(connection_methods):
    for attempt in connection_methods:
        connected = attempt.connect()
        if connected:
            return True
    return False


def interactive_connection(connection_methods):
    print("Connection methods: ")
    print("0 - DHCP")
    print("1 - Infer from ARP traffic")
    print("2 - Infer from TCP data traffic")

    i = int(input("Select a connection method: "))

    if 0 <= i < len(connection_methods):
        connection_method = connection_methods[i]
        return connection_method.connect()
    else:
        print("Invalid choice ! ! !")
        interactive_connection(connection_methods)


def print_help():
    print("Usage:\n sudo autoconnect [path to configuration file]")


def main():
    batch = False
    conf = Configuration()

    if len(sys.argv) > 1:
        if sys.argv.__contains__("--help") or sys.argv.__contains__("-h"):
            print_help()
            exit(0)
        try:
            conf.parse_configurations(sys.argv[1])
        except FileNotFoundError:
            print("Configuration file not found.")
            exit(0)

        batch = True
    else:
        interfaces = get_if_list()
        print("Available interfaces: ")
        for i in range(0, len(interfaces)):
            print(str(i) + " - " + interfaces[i])

        i = int(input("Select an interface to connect: "))
        if 0 <= i < len(interfaces):
            conf.interface = str(interfaces[i])
            batch = False
        else:
            exit(0)

    connection_methods = [DHCPAttempt(conf.interface), BroadcastAttempt(conf.interface), DataAttempt(conf.interface)]
    captive_portal_handlers = {"WifiDog": WifiDogCaptivePortal(), "Nodogsplash": NodogsplashCaptivePortal(),
                               "ZeroShell": ZeroShellCaptivePortal()}

    if batch:
        connected = batch_connection(connection_methods)
    else:
        connected = interactive_connection(connection_methods)

    if connected:
        try:
            resp = request(method='GET', url="http://clients3.google.com/generate_204", allow_redirects=False)
            print(resp.status_code)
            print(resp.history)
            print(resp.url)
            if resp.is_redirect:
                print("Captive portal detected! Trying to connect . . .")
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


if __name__ == "__main__":
    main()
