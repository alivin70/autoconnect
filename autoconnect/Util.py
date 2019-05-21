import struct
import socket


def ip_to_int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

# int(ipaddress.IPv4Address("192.168.0.1"))
# str(ipaddress.IPv4Address(3232235521))