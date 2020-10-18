import dpkt
import Ethernet
import os

print("WARNING - FILES MUST BE UNDER FOLDER WITH NAME 'test-files'")
filename = 'test-files/' + input("Please enter file which you want to sniff WITHOUT .pcap: ") + '.pcap'
if os.path.exists(filename):
    with open(filename, 'rb') as file:
        try:
            pcapFile = dpkt.pcap.Reader(file)
            serial_number = 0
            sending_nodes_IP = {}
            dest_nodes_IP = {}
            sending_nodes_IP_w_values = {}

            for ts, buf in pcapFile:
                eth = dpkt.ethernet.Ethernet(buf)
                serial_number += 1
                type = Ethernet.ethernet11(buf)
                print("Serial number No. ", serial_number)
                print("Time stamp ", ts)

                print("The frame length in bytes provided by the pcap API {} B".format(len(buf)))
                if len(buf) <= 60:
                    print("The frame length in bytes provided by the pcap API 64 B")
                else:
                    print("The frame length in bytes provided by media {} B ".format(len(buf) + 4))

                print("Frame type: {}".format(type))
                print("Destenation Mac Address: ", Ethernet.prettifyMac(buf[0:6]))
                print("Source Mac Address: ", Ethernet.prettifyMac(buf[6:12]))

                if type == Ethernet.Ethernet_II_str:
                    Ethernet.formatData(buf[14:])
                if int.from_bytes(buf[12:14], "big") == Ethernet.ETH_TYPE_IP:
                    ip_header = buf[14:34]
                    version_header_length = int.from_bytes(buf[14:15], "big")
                    version = version_header_length >> 4
                    header_length = (version_header_length & 15) * 4
                    total_length = int.from_bytes(ip_header[2:4], "big")
                    # print(total_length)
                    src_ip = Ethernet.prettifyIp(ip_header[12:16])
                    dest_ip = Ethernet.prettifyIp(ip_header[16:20])
                    # updating list of sending nodes
                    sending_nodes_IP[src_ip] = 1
                    dest_nodes_IP[dest_ip] = 1
                    print("IP version", version)
                    print("IP Header Length", header_length)
                    print("Source IP address", src_ip)
                    print("Destination IP address", dest_ip)

                    # new_src_obj = source_node.SourceNode(src_ip, total_length)
                    sending_nodes_IP_w_values[src_ip] = total_length

                    protocol = int.from_bytes(ip_header[9:10], "big")
                    if protocol == 6:
                        print("TCP")
                        tcp = buf[34:66]
                        tcp_src_port = int.from_bytes(tcp[0:2], "big")
                        tcp_dst_port = int.from_bytes(tcp[2:4], "big")
                        if tcp_src_port == 80 or tcp_dst_port == 80:
                            print("HTTP")
                        if tcp_src_port == 443 or tcp_dst_port == 443:
                            print("HTTPS")
                        if tcp_src_port == 22 or tcp_dst_port == 22:
                            print("SSH")
                        if tcp_src_port == 21 or tcp_dst_port == 21:
                            print("FTP-CONTROL")
                        if tcp_src_port == 20 or tcp_dst_port == 20:
                            print("FTP-DATA")
                        if tcp_src_port == 23 or tcp_dst_port == 23:
                            print("TELNET")
                    elif protocol == 17:
                        print("UDP")
                        udp = buf[34:66]
                        if int.from_bytes(udp[0:2], "big") == 69 or int.from_bytes(udp[2:4], "big") == 69:
                            print("TFTP")
                    elif protocol == 1:
                        print("ICMP")
                        icmp_header = buf[34:66]
                        code = int.from_bytes(icmp_header[1:2], "big")
                        if code == 0:
                            print("Echo Reply")
                        if code == 3:
                            print("TFTP")
                            print("Destination Unreachable")
                        if code == 4:
                            print("Source Quench")
                        if code == 5:
                            print("Redirect")
                        if code == 8:
                            print("Echo")
                        if code == 9:
                            print("Router Advertisement")
                        if code == 10:
                            print("Router Selection")
                        if code == 11:
                            print("Time Exceeded")
                        if code == 12:
                            print("Parameter Problem")
                        if code == 13:
                            print("Timestamp")
                        if code == 14:
                            print("Timestamp Reply")
                        if code == 15:
                            print("Information Request")
                        if code == 16:
                            print("Information Reply")
                        if code == 17:
                            print("Address Mask Request")
                        if code == 18:
                            print("Address Mask Reply")
                        if code == 30:
                            print("TRACEROUTE")
                if int.from_bytes(buf[12:14], "big") == Ethernet.ETH_TYPE_ARP:
                    print("ARP")
                if int.from_bytes(buf[12:14], "big") == Ethernet.ETH_TYPE_IP6:
                    print("IP6")
                print("============================================================")
            print("Source IPv4 addresses")
            # print('\n'.join(x for x in sending_nodes_IP))
            print('\n'.join(x for x in list(sending_nodes_IP)))
            print("Destination IPv4 addresses")
            # print('\n'.join(x for x in sending_nodes_IP))
            print('\n'.join(x for x in list(dest_nodes_IP)))
            print("Node with maximum amount of sent packets")
            print(max(sending_nodes_IP_w_values.items(), key=lambda k: k[1]))
            print("**************************The end*********************************")
            file.close()
        except Exception as e:
            print(e)
        except (OSError, IOError) as e:
            print("Error opening file")
else:
    print("No such file or directory")
