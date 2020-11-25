import scapy.all as scp;

info = {
    "count": 0,
    "count_tcp": 0,
    "sum_len_tcp": 0,
    "max_tcp": 0,
    "min_tcp": 0,
    "count_udp": 0,
    "sum_len_udp": 0,
    "max_udp": 0,
    "min_udp": 0
}

pkts_udp_size = []
pkts_tcp_size = []


def get_interfaces():
    return scp.ifaces.show()


def select_interface(index):
    try:
        return scp.ifaces.dev_from_index(index)
    except:
        print('Enter a Valid Index For Interface From List.')
        return 0


def show_filter(pkt):
    ip_src = pkt[scp.IP].src
    ip_dst = pkt[scp.IP].dst
    if scp.TCP in pkt:
        pkt_tcp_size = len(pkt)
        pkts_tcp_size.append(pkt_tcp_size)
        pkts_tcp_size.sort()
        info["count_tcp"] += 1
        info["count"] += 1
        info["sum_len_tcp"] += pkt_tcp_size
        avg_tcp = info["sum_len_tcp"] / info["count_tcp"]
        info["min_tcp"] = pkts_tcp_size[0]
        info["max_tcp"] = pkts_tcp_size[len(pkts_tcp_size) - 1]
        tcp_sport = pkt[scp.TCP].sport
        tcp_dport = pkt[scp.TCP].dport
        print("Packet #" + str(info["count"]) + "\nProtocol: TCP   /   " + "SourceIp: " + str(ip_src) + "    /    SourcePort: " + str(tcp_sport)  +
              "    /   " + "DestinationIp: " + str(ip_dst) + "  /   DestinationPort: " + str(tcp_dport))
        print("TCP Packet Count: {}   "
              "/   Average TCP Length:  {}   "
              "/   Maximum TCP Packet: {}   "
              "/   Minimum TCP Packet: {}"
              "".format(info["count_tcp"], avg_tcp, info["max_tcp"], info["min_tcp"]))
    if scp.UDP in pkt:
        info["count"] += 1
        pkt_udp_size = len(pkt)
        pkts_udp_size.append(pkt_udp_size)
        pkts_udp_size.sort()
        info["count_udp"] += 1
        info["sum_len_udp"] += pkt_udp_size
        info["min_udp"] = pkts_udp_size[0]
        info["max_udp"] = pkts_udp_size[len(pkts_udp_size) - 1]
        avg_udp = info["sum_len_udp"] / info["count_udp"]
        udp_sport = pkt[scp.UDP].sport
        udp_dport = pkt[scp.UDP].dport
        print("Packet #" + str(info["count"]) +
              "\nProtocol: UDP   /   " + "SourceIp: " + str(
            ip_src) + "   /   SourcePort: " + str(udp_sport) +
              "   /   " + "DestinationIp: " + str(ip_dst) +
              "   /   DestinationPort: " + str(udp_dport))
        print("UDP Packet Count: {}   "
              "/   Average UDP Length:  {}   "
              "/   Maximum UDP Packet: {}   "
              "/   Minimum UDP Packet: {}"
              "".format(info["count_udp"], avg_udp, info["max_udp"], info["min_udp"]))

    print("----------------------------------------------------------------------------------------------------------")


def custom_filter(pkt):
    if scp.IP in pkt:
        show_filter(pkt)


def main():
    print("My Interfaces: ")
    print("------------------------------------------------")
    get_interfaces()
    index = input("Select Index One Of Them For Sniffing: ")
    selected_interface = select_interface(index);
    while selected_interface == 0:
        print("My Interfaces: ")
        print("------------------------------------------------")
        get_interfaces()
        print("------------------------------------------------")
        index = input("Select Index One Of Them For Sniffing: ")
        selected_interface = select_interface(index)
    scp.sniff(iface=selected_interface, prn=custom_filter)


if __name__ == '__main__':
    main()
