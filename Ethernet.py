# Ethernet payload types - http://standards.ieee.org/regauth/ethertype
ETH_TYPE_UNKNOWN = 0x0000
ETH_TYPE_EDP = 0x00bb  # Extreme Networks Discovery Protocol
ETH_TYPE_PUP = 0x0200  # PUP protocol
ETH_TYPE_IP = 0x0800  # IP protocol
ETH_TYPE_ARP = 0x0806  # address resolution protocol
ETH_TYPE_AOE = 0x88a2  # AoE protocol
ETH_TYPE_CDP = 0x2000  # Cisco Discovery Protocol
ETH_TYPE_DTP = 0x2004  # Cisco Dynamic Trunking Protocol
ETH_TYPE_REVARP = 0x8035  # reverse addr resolution protocol
ETH_TYPE_8021Q = 0x8100  # IEEE 802.1Q VLAN tagging
ETH_TYPE_8021AD = 0x88a8  # IEEE 802.1ad
ETH_TYPE_QINQ1 = 0x9100  # Legacy QinQ
ETH_TYPE_QINQ2 = 0x9200  # Legacy QinQ
ETH_TYPE_IPX = 0x8137  # Internetwork Packet Exchange
ETH_TYPE_IP6 = 0x86DD  # IPv6 protocol
ETH_TYPE_PPP = 0x880B  # PPP
ETH_TYPE_MPLS = 0x8847  # MPLS
ETH_TYPE_MPLS_MCAST = 0x8848  # MPLS Multicast
ETH_TYPE_PPPoE_DISC = 0x8863  # PPP Over Ethernet Discovery Stage
ETH_TYPE_PPPoE = 0x8864  # PPP Over Ethernet Session Stage
ETH_TYPE_LLDP = 0x88CC  # Link Layer Discovery Protocol
ETH_TYPE_TEB = 0x6558  # Transparent Ethernet Bridging
ETH_TYPE_PROFINET = 0x8892  # PROFINET protocol

Ethernet_II_str = "Ethernet II";
IEEE_Novel_8023_RAW_str = "IEEE Novel 802.3 RAW";
IEEE_8023_LLC_SNAP_str = "IEEE 802.3 LLC + SNAP";
IEEE_8023_LLC_str = "IEEE 802.3 LLC";

TYPE = 0x0000


def prettifyMac(mac_string):
    return ':'.join(f'{x:02x}' for x in mac_string)


def prettifyIp(mac_string):
    return '.'.join(f'{int(x)}' for x in mac_string)


def ethernet11(buf):
    type = buf[12:14]
    if int.from_bytes(type, "big") > 1500:
        return Ethernet_II_str
    elif buf[14:].startswith(b'\xff\xff'):
        return IEEE_Novel_8023_RAW_str
    elif buf[14] == 170 and buf[15] == 170:
        return IEEE_8023_LLC_SNAP_str
    else:
        return IEEE_8023_LLC_str


def formatData(data):
    counter = 0
    output = ""
    for ele in ' '.join(f'{x:02x}' for x in data).split(" "):
        output = output + " " + ele
        counter = counter + 1
        if counter % 4 == 0:
            output += " "
        if counter % 8 == 0:
            output += " "
        if counter == 16:
            print(output)
            output = ""
            counter = 0
