import dpkt
import Ethernet
import os
import myColors
import random

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
            arp_frames = []
            arp_requests_without_pair_frames = []
            arp_requests_without_pair_ip_frames = []
            arp_printed_frames = {}
            dns_nad_udp = []
            dns_nad_udp_ids = []
            for ts, buf in pcapFile:
                eth = dpkt.ethernet.Ethernet(buf)
                serial_number += 1
                type = Ethernet.ethernet11(buf)
                print(
                    myColors.myColors.red + "Serial number No. {} ".format(serial_number) + myColors.myColors.ENDC)
                print(myColors.myColors.red + "Time stamp {}".format(ts) + myColors.myColors.ENDC)

                print(myColors.myColors.red + "The frame length in bytes provided by the pcap API {} B".format(
                    len(buf)) + myColors.myColors.ENDC)
                if len(buf) <= 60:
                    print(
                        myColors.myColors.red + "The frame length in bytes provided by the pcap API 64 B" + myColors.myColors.ENDC)
                else:
                    print(myColors.myColors.red + "The frame length in bytes provided by media {} B ".format(
                        len(buf) + 4) + myColors.myColors.ENDC)

                print(myColors.myColors.red + "Frame type: {}".format(type))
                print(myColors.myColors.red + "Destination Mac Address: ",
                      Ethernet.prettifyMac(buf[0:6]) + myColors.myColors.ENDC)
                print(myColors.myColors.red + "Source Mac Address: ",
                      Ethernet.prettifyMac(buf[6:12]) + myColors.myColors.ENDC)

                if int.from_bytes(buf[12:14], "big") == Ethernet.ETH_TYPE_IP:
                    version_header_length = int.from_bytes(buf[14:15], "big")
                    version = version_header_length >> 4
                    header_length = (version_header_length & 15) * 4
                    end_of_ip_header = 14 + header_length
                    ip_header = buf[14:end_of_ip_header]

                    total_length = int.from_bytes(ip_header[2:4], "big")
                    # print(total_length)
                    src_ip = Ethernet.prettifyIp(ip_header[12:16])
                    dest_ip = Ethernet.prettifyIp(ip_header[16:20])
                    # updating list of sending nodes
                    sending_nodes_IP[src_ip] = 1
                    dest_nodes_IP[dest_ip] = 1
                    print(myColors.myColors.red + "IP version {}".format(version) + myColors.myColors.ENDC)
                    print(myColors.myColors.red + "IP Header Length {}".format(header_length) + myColors.myColors.ENDC)
                    print(myColors.myColors.red + "Source IP address {}".format(src_ip) + myColors.myColors.ENDC)
                    print(myColors.myColors.red + "Destination IP address {}".format(dest_ip) + myColors.myColors.ENDC)

                    # new_src_obj = source_node.SourceNode(src_ip, total_length)
                    if src_ip in sending_nodes_IP_w_values:
                        sending_nodes_IP_w_values[src_ip] += total_length
                    else:
                        sending_nodes_IP_w_values[src_ip] = total_length

                    protocol = int.from_bytes(ip_header[9:10], "big")
                    if protocol == 6:
                        print(myColors.myColors.red + "TCP" + myColors.myColors.ENDC)
                        tcp = buf[end_of_ip_header:end_of_ip_header + 32]
                        tcp_src_port = int.from_bytes(tcp[0:2], "big")
                        tcp_dst_port = int.from_bytes(tcp[2:4], "big")
                        print(myColors.myColors.red + "Source Port: ".format(tcp_src_port) + myColors.myColors.ENDC)
                        print(
                            myColors.myColors.red + "Destination Port: ".format(tcp_dst_port) + myColors.myColors.ENDC)
                        if tcp_src_port == 80 or tcp_dst_port == 80:
                            print(myColors.myColors.red + "HTTP" + myColors.myColors.ENDC)
                        if tcp_src_port == 443 or tcp_dst_port == 443:
                            print(myColors.myColors.red + "HTTPS" + myColors.myColors.ENDC)
                        if tcp_src_port == 22 or tcp_dst_port == 22:
                            print(myColors.myColors.red + "SSH" + myColors.myColors.ENDC)
                        if tcp_src_port == 21 or tcp_dst_port == 21:
                            print(myColors.myColors.red + "FTP-CONTROL" + myColors.myColors.ENDC)
                        if tcp_src_port == 20 or tcp_dst_port == 20:
                            print(myColors.myColors.red + "FTP-DATA" + myColors.myColors.ENDC)
                        if tcp_src_port == 23 or tcp_dst_port == 23:
                            print(myColors.myColors.red + "TELNET" + myColors.myColors.ENDC)
                    elif protocol == 17:
                        print(myColors.myColors.red + "UDP" + myColors.myColors.ENDC)
                        udp = buf[end_of_ip_header:66]
                        udp_src_port = int.from_bytes(udp[0:2], "big")
                        udp_dst_port = int.from_bytes(udp[2:4], "big")

                        # show the dns packets
                        if udp_src_port == 53 or udp_dst_port == 53:
                            print(myColors.myColors.orange + "DNS" + myColors.myColors.ENDC)
                            print(
                                myColors.myColors.orange + "Source Port: {}".format(
                                    udp_src_port) + myColors.myColors.ENDC)
                            print(myColors.myColors.orange + "Destination Port: {}".format(
                                udp_dst_port) + myColors.myColors.ENDC)
                            dns_nad_udp_ids.append(serial_number)
                            dns_nad_udp.append(udp)
                        else:
                            print(
                                myColors.myColors.red + "Source Port: {}".format(udp_src_port) + myColors.myColors.ENDC)
                            print(myColors.myColors.red + "Destination Port: {}".format(
                                udp_dst_port) + myColors.myColors.ENDC)

                        if int.from_bytes(udp[0:2], "big") == 69 or int.from_bytes(udp[2:4], "big") == 69:
                            print(myColors.myColors.red + "TFTP" + myColors.myColors.ENDC)
                    elif protocol == 1:
                        print(myColors.myColors.red + "ICMP" + myColors.myColors.ENDC)
                        icmp_header = buf[end_of_ip_header:66]
                        code = int.from_bytes(icmp_header[1:2], "big")
                        if code == 0:
                            print(myColors.myColors.red + "Echo Reply" + myColors.myColors.ENDC)
                        if code == 3:
                            print(myColors.myColors.red + "TFTP" + myColors.myColors.ENDC)
                            print(myColors.myColors.red + "Destination Unreachable" + myColors.myColors.ENDC)
                        if code == 4:
                            print(myColors.myColors.red + "Source Quench" + myColors.myColors.ENDC)
                        if code == 5:
                            print(myColors.myColors.red + "Redirect" + myColors.myColors.ENDC)
                        if code == 8:
                            print(myColors.myColors.red + "Echo" + myColors.myColors.ENDC)
                        if code == 9:
                            print(myColors.myColors.red + "Router Advertisement" + myColors.myColors.ENDC)
                        if code == 10:
                            print(myColors.myColors.red + "Router Selection" + myColors.myColors.ENDC)
                        if code == 11:
                            print(myColors.myColors.red + "Time Exceeded" + myColors.myColors.ENDC)
                        if code == 12:
                            print(myColors.myColors.red + "Parameter Problem" + myColors.myColors.ENDC)
                        if code == 13:
                            print(myColors.myColors.red + "Timestamp" + myColors.myColors.ENDC)
                        if code == 14:
                            print(myColors.myColors.red + "Timestamp Reply" + myColors.myColors.ENDC)
                        if code == 15:
                            print(myColors.myColors.red + "Information Request" + myColors.myColors.ENDC)
                        if code == 16:
                            print(myColors.myColors.red + "Information Reply" + myColors.myColors.ENDC)
                        if code == 17:
                            print(myColors.myColors.red + "Address Mask Request" + myColors.myColors.ENDC)
                        if code == 18:
                            print(myColors.myColors.red + "Address Mask Reply" + myColors.myColors.ENDC)
                        if code == 30:
                            print(myColors.myColors.red + "TRACEROUTE" + myColors.myColors.ENDC)

                if int.from_bytes(buf[12:14], "big") == Ethernet.ETH_TYPE_ARP:
                    print(myColors.myColors.red + "ARP" + myColors.myColors.ENDC)
                    arp = buf[14:46]
                    arp_frames.append(arp)
                    Ethernet.printARP(arp, 1)

                if int.from_bytes(buf[12:14], "big") == Ethernet.ETH_TYPE_IP6:
                    print(myColors.myColors.red + "IP6" + myColors.myColors.ENDC)
                print("-----------------------Browse in HEX-----------------------------")
                Ethernet.formatData(buf)
                print("-----------------------End of Browsing in HEX--------------------")

            print("------ARP PAIRS (IF IT'S EXISTED)--------")
            for arp_frame in arp_frames:
                for arp_frame2 in arp_frames:
                    # if source ip == target ip => pair
                    src_f1_protocol_address = arp_frame[14:18]
                    dest_f1_protocol_address = arp_frame[24:28]
                    src_f2_protocol_address = arp_frame2[14:18]
                    dest_f2_protocol_address = arp_frame2[24:28]
                    arp_frame1_type = arp_frame[6:8]
                    arp_frame2_type = arp_frame2[6:8]
                    if int.from_bytes(arp_frame1_type, "big") == 1 and int.from_bytes(arp_frame2_type, "big") == 2 and \
                            Ethernet.prettifyIp(src_f1_protocol_address) == Ethernet.prettifyIp(
                        dest_f2_protocol_address) and \
                            Ethernet.prettifyIp(dest_f1_protocol_address) == Ethernet.prettifyIp(
                        src_f2_protocol_address) and \
                            src_f1_protocol_address not in arp_printed_frames and src_f2_protocol_address \
                            not in arp_printed_frames:
                        arp_printed_frames[src_f1_protocol_address] = src_f1_protocol_address
                        arp_printed_frames[src_f2_protocol_address] = src_f2_protocol_address
                        color_No = random.randint(2, 12)

                        Ethernet.printARP(arp_frame, color_No)
                        Ethernet.printARP(arp_frame2, color_No)
                        print("######################################")

            if len(arp_printed_frames) == 0:
                print("NO ARP PAIRS WHERE FOUNDED")
            print("---END - ARP PAIRS (IF IT'S EXISTED)-----")
            print("--- DNS PACKETS-----")
            no = 0
            for udp1 in dns_nad_udp:
                print(
                    myColors.myColors.red + "Serial number No. {} ".format(
                        dns_nad_udp_ids[no]) + myColors.myColors.ENDC)
                no += 1
                udp_src_port1 = int.from_bytes(udp1[0:2], "big")
                udp_dst_port1 = int.from_bytes(udp1[2:4], "big")

                print(myColors.myColors.orange + "DNS" + myColors.myColors.ENDC)
                print(
                    myColors.myColors.orange + "Source Port: {}".format(
                        udp_src_port1) + myColors.myColors.ENDC)
                print(myColors.myColors.orange + "Destination Port: {}".format(
                    udp_dst_port1) + myColors.myColors.ENDC)
                print("================================================")
            print("---END - DNS PACKETS-----")

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
