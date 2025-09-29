import socket
import struct

def main():
    # AF_PACKET is for Linux, SOCK_RAW for raw packets
    try:
        # For Windows, use socket.AF_INET and socket.IPPROTO_IP
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind(("0.0.0.0", 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        print("Sniffing on Windows...")
    except AttributeError:
        # Linux/Unix systems
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print("Sniffing on Linux/Unix...")
    except Exception as e:
        print("Socket could not be created. Try running as administrator/root.")
        print(e)
        return

    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            # For Linux, skip Ethernet header (first 14 bytes)
            if hasattr(socket, 'AF_PACKET') and sniffer.family == socket.AF_PACKET:
                raw_data = raw_data[14:]

            # Unpack IP header
            ip_header = raw_data[:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            protocol = iph[6]

            print(f"IP Packet: {src_ip} -> {dst_ip}, Protocol: {protocol}")
    except KeyboardInterrupt:
        print("\nStopping packet sniffer.")
        if hasattr(sniffer, 'ioctl'):
            # Windows cleanup
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    main()