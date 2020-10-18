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
                    # formatData1(buf[14:])
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

                    protocol = ip_header[9:10]
                    if int.from_bytes(protocol, "big") == 6:
                        print("TCP")
                    elif int.from_bytes(protocol, "big") == 17:
                        print("UDP")
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
