import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '

DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '

# Main function to sniff the network (Windows compatible)
def main():
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((socket.gethostbyname(socket.gethostname()), 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except PermissionError:
        print("[ERROR] Run this script as Administrator.")
        return
    except OSError as e:
        print(f"[ERROR] Socket error: {e}")
        return

    print("[*] Sniffer started. Press Ctrl+C to stop.\n")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)

            # Windows captures at IP layer — no Ethernet header
            result = ipv4packet(raw_data)
            if result is None:
                continue

            version, header_length, ttl, proto, src, target, data = result

            print('\nIPv4 Packet:')
            print(TAB_1 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_1 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # ICMP
            if proto == 1:
                result = icmp_packet(data)
                if result:
                    icmp_type, code, checksum, data = result
                    print(TAB_1 + 'ICMP Packet:')
                    print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                    print(format_multi_line(DATA_TAB_3, data))

            # TCP
            elif proto == 6:
                result = tcp_segment(data)
                if result:
                    src_port, dest_port, sequence, acknowledgment, \
                    flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = result
                    print(TAB_1 + 'TCP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                    print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                    print(TAB_2 + 'Flags:')
                    print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(
                        flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                    print(format_multi_line(DATA_TAB_3, data))

            # UDP
            elif proto == 17:
                result = udp_segment(data)
                if result:
                    src_port, dest_port, size, data = result
                    print(TAB_1 + 'UDP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(
                        src_port, dest_port, size))
                    print(format_multi_line(DATA_TAB_3, data))

            # Other IPv4
            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_multi_line(DATA_TAB_2, data))

    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer...")
    finally:
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)   # Always turn off promiscuous mode
        conn.close()
        print("[*] Socket closed.")


# Unpack IPv4 packet — returns None if data is too short
def ipv4packet(data):
    if len(data) < 20:
        return None
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# Returns properly formatted IPv4 address (e.g. 192.168.1.1)
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpack ICMP packet — returns None if data is too short
def icmp_packet(data):
    if len(data) < 4:
        return None
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpack TCP segment — returns None if data is too short
def tcp_segment(data):
    if len(data) < 14:
        return None
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = \
        struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, \
           flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Unpack UDP segment — returns None if data is too short
def udp_segment(data):
    if len(data) < 8:
        return None
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# Format multi-line hex data for readable output
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()