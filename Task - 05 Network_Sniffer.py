#Network_Sniffer
import socket
import struct
import textwrap

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def main():
    interface = input("Please enter the network interface to sniff (e.g., eth0, wlan0): ")

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    conn.bind((interface, 0))

    with open('captured_packets.txt', 'w') as f:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            f.write('\nEthernet Frame:\n')
            f.write(f'Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}\n')

            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
                f.write('IPv4 Packet:\n')
                f.write(f'Version: {version}, Header Length: {header_length}, TTL: {ttl}\n')
                f.write(f'Protocol: {proto}, Source: {src}, Target: {target}\n')

                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)
                    f.write('ICMP Packet:\n')
                    f.write(f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}\n')
                    f.write('Data:\n')
                    f.write(format_multi_line('\t', data) + '\n')

                elif proto == 6:
                    (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                    f.write('TCP Segment:\n')
                    f.write(f'Source Port: {src_port}, Destination Port: {dest_port}\n')
                    f.write(f'Sequence: {sequence}, Acknowledgment: {acknowledgement}\n')
                    f.write('Flags:\n')
                    f.write(f'URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}\n')
                    f.write('Data:\n')
                    f.write(format_multi_line('\t', data) + '\n')

                elif proto == 17:
                    src_port, dest_port, length, data = udp_segment(data)
                    f.write('UDP Segment:\n')
                    f.write(f'Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}\n')

                else:
                    f.write('Other IPv4 Data:\n')
                    f.write(format_multi_line('\t', data) + '\n')
            else:
                f.write('Non-IPv4 Data:\n')
                f.write(format_multi_line('\t', data) + '\n')

if __name__ == '__main__':
    main()
