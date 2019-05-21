import os


def setup_interface(interface, ip_address, subnet_mask):
    # os.system("sudo ifconfig %s down" % (interface))
    # os.system("sudo ifconfig %s %s netmask %s" % (interface, ip_address, subnet_mask))
    # os.system("sudo ifconfig %s up" % (interface))
    pass

def setup_dns(dnsServer):
    # os.system('sudo echo "nameserver %s" > /etc/resolv.conf' % (dnsServer))
    pass

def setup_default_gateway(router):
    # os.system("sudo route add default gw %s" % (router))
    pass