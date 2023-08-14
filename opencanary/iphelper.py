import struct
import socket


def ip2int(addr):
    """
    Convert an IP in string format to decimal format
    """

    return struct.unpack("!I", socket.inet_aton(addr))[0]


def check_ip(ip, network_range):
    """
    Test if the IP is in range

    Range is expected to be in CIDR notation format. If no MASK is
    given /32 is used. It return True if the IP is in the range.
    """

    netItem = str(network_range).split("/")
    rangeIP = netItem[0]
    if len(netItem) == 2:
        rangeMask = int(netItem[1])
    else:
        rangeMask = 32

    try:
        ripInt = ip2int(rangeIP)
        ipInt = ip2int(ip)
        result = not ((ipInt ^ ripInt) & 0xFFFFFFFF << (32 - rangeMask))
    except:  # noqa: E722
        result = False

    return result
