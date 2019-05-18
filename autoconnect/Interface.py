import os


def setupInterface(interface, ipAddress, subnet_mask):
    os.system("sudo ifconfig %s down" % (interface))
    os.system("sudo ifconfig %s %s netmask %s" % (interface, ipAddress, subnet_mask))
    os.system("sudo ifconfig %s up" % (interface))

def setupDns(dnsServer):
    # os.system('sudo echo "nameserver %s" > /etc/resolv.conf' % (dnsServer))
    pass

def setupDefaultGateway(router):
    os.system("sudo route add default gw %s" % (router))