import myColors

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
Ethernet_str = "Ethernet"
Ethernet_IEEE_str = "IEEE 802 LAN"
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


def switch_color(argument):
    switcher = {
        1: myColors.myColors.red,
        2: myColors.myColors.green,
        3: myColors.myColors.blue,
        4: myColors.myColors.lightblue,
        5: myColors.myColors.lightcyan,
        6: myColors.myColors.cyan,
        7: myColors.myColors.lightred,
        8: myColors.myColors.pink,
        9: myColors.myColors.yellow,
        10: myColors.myColors.lightgreen,
        11: myColors.myColors.lightgrey,
        12: myColors.myColors.orange,
        13: myColors.myColors.purple,
    }
    return switcher.get(argument)


def printARP(data, colorNo):
    #  arp = buf[14:46]
    arp = data
    hardware_address_type = arp[0:2]
    protocol_address_type = arp[2:4]
    hardware_address_length = arp[4:5]
    protocol_address_length = arp[5:6]
    arp_type = arp[6:8]
    src_hardware_address = arp[8:14]
    src_protocol_address = arp[14:18]
    dest_hardware_address = arp[18:24]
    dest_protocol_address = arp[24:28]
    color = switch_color(colorNo)
    if int.from_bytes(arp_type, "big") == 1:
        print(color+"ARP-REQUEST"+myColors.myColors.ENDC)
    if int.from_bytes(arp_type, "big") == 2:
        print(color+"ARP-REPLY"+myColors.myColors.ENDC)
    print(color+"Hardware Type: ".format(checkHWaddressType(hardware_address_type))+myColors.myColors.ENDC)
    if int.from_bytes(protocol_address_type, "big") == ETH_TYPE_IP:
        print(color+"Protocol Type: IPV4"+myColors.myColors.ENDC)
    print(color+"Hardware Address Length: {} B".format(int.from_bytes(hardware_address_length, "big"))+myColors.myColors.ENDC)
    print(color+"Protocol Address Length: {} B".format(int.from_bytes(protocol_address_length, "big"))+myColors.myColors.ENDC)
    print(color+"Sender Mac Address: {}".format(prettifyMac(src_hardware_address))+myColors.myColors.ENDC)
    print(color+"Sender IP Address: {}".format(prettifyIp(src_protocol_address))+myColors.myColors.ENDC)
    print(color+"Target Mac Address: {}".format(prettifyMac(dest_hardware_address))+myColors.myColors.ENDC)
    print(color+"Target IP Address: {}".format(prettifyIp(dest_protocol_address))+myColors.myColors.ENDC)


def checkHWaddressType(data):
    if int.from_bytes(data, "big") == 1:
        return Ethernet_str
    elif int.from_bytes(data, "big") == 6:
        return Ethernet_IEEE_str


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
