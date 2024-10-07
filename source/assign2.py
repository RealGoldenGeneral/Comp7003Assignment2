from scapy.all import sniff

class PacketCapture:
    def __init__(self, interface, capture_filter, packet_count):
        self.interface = interface
        self.capture_filter = capture_filter
        self.packet_count  = packet_count

    def _parse_tcp_header(self, hex_data):
        # TCP header is typically the 20 bytes after the IPv4 header
        source_port = hex_data[68:72]
        destination_port = hex_data[72:76]
        sequence_number = hex_data[76:84]
        acknowledgement_number = hex_data[84:92]
        data_offset = hex_data[92]
        flags = hex_data[93:96]
        window_size = hex_data[96:100]
        checksum = hex_data[100:104]
        urgent_pointer = hex_data[105:108]

        # Convert from hexadecimal to decimal
        source_port = int(source_port, 16)
        destination_port = int(destination_port, 16)
        sequence_number = int(sequence_number, 16)
        acknowledgement_number = int(acknowledgement_number, 16)
        data_offset = int(data_offset, 16)
        window_size = int(window_size, 16)
        urgent_pointer = int (urgent_pointer, 16)

        # Convert from hexadecimal to binary
        flags = bin(int('1' + flags, 16))
        flags = flags[3:]

        # Store flags
        accurate_ecn = flags[3]
        congestion_window_reduced = flags[4]
        ecn_echo = flags[5]
        urgent = flags[6]
        acknowledgement = flags[7]
        push = flags[8]
        reset = flags[9]
        syn = flags[10]
        fin = flags[11]

        print(f"Source port: {source_port}")
        print(f"Destination port: {destination_port}")
        print(f"Sequence number: {sequence_number}")
        print(f"Acknowledgement number: {acknowledgement_number}")
        print(f"Data offset: {data_offset}")
        print(f"Accurate ECN: {accurate_ecn}")
        print(f"Congestion Window Reduced: {congestion_window_reduced}")
        print(f"ECN Echo: {ecn_echo}")
        print(f"Urgent: {urgent}")
        print(f"Acknowledgement: {acknowledgement}")
        print(f"Push: {push}")
        print(f"Reset: {reset}")
        print(f"SYN: {syn}")
        print(f"FIN: {fin}")
        print(f"Window size: {window_size}")
        print(f"Checksum: 0x{checksum}")
        print(f"Urgent Pointer: {urgent_pointer}")

    def _parse_udp_header(self, hex_data):
        # UDP header is the 8 bytes (16 hex characters) after the IPv4 header
        source_port = hex_data[68:72]
        destination_port = hex_data[72:76]
        length =  hex_data[76:80]
        checksum = hex_data[80:84]

        # Convert from hexadecimal to decimal
        source_port = int(source_port, 16)
        destination_port = int(destination_port, 16)
        length = int(length, 16)

        print(f"Source port: {source_port}")
        print(f"Destination port: {destination_port}")
        print(f"Length: {length}")
        print(f"Checksum: {checksum}")

    def _parse_ipv4_header(self, hex_data):
        # IPv4 header is typically the 20 bytes (40 hex characters) after the ethernet header
        version = hex_data[28]
        internet_header_length = hex_data[29]
        type_of_service = hex_data[30:32]
        total_length = hex_data[32:36]
        identification = hex_data[36:40]
        flags = hex_data[40:42]
        fragment_offset  = hex_data[40:44]
        time_to_live = hex_data[44:46]
        protocol = hex_data[46:48]
        checksum = hex_data[49:52]
        source_address = hex_data[52:60]
        destination_address = hex_data[60:68]

        # Convert from hexadecimal to decimal
        version = int(version, 16)
        internet_header_length = int(internet_header_length, 16)
        total_length = int(total_length, 16)
        time_to_live = int(time_to_live, 16)
        protocol = int(protocol, 16)

        # Convert from hexadecimal to binary
        flags = bin(int(flags, 16))
        fragment_offset = bin(int(fragment_offset, 16))

        # Store flags
        dont_fragment = flags[2]
        more_fragments = flags[3]

        # Store fragment offset
        fragment_offset = fragment_offset[4:]

        # Convert hex IP addresses into readable format
        source_address_bytes_list = ["".join(source_address)[i:i+2] for i in range(0, 8, 2)]
        source_address_bytes_list = [int(x, 16) for x in source_address_bytes_list]
        source_address_readable = ".".join(str(x) for x in source_address_bytes_list)
        destination_address_bytes_list = ["".join(destination_address)[i:i+2] for i in range(0, 8, 2)]
        destination_address_bytes_list = [int(x, 16) for x in destination_address_bytes_list]
        destination_address_readable = ".".join(str(x) for x in destination_address_bytes_list)

        print(f"Version: {version}")
        print(f"Internet Header Length: {internet_header_length}")
        print(f"Type of Service: {type_of_service}")
        print(f"Total Length: {total_length}")
        print(f"Identification: {identification}")
        print(f"Don't Fragment: {dont_fragment}")
        print(f"More fragments: {more_fragments}")
        print(f"Fragment offsets: {fragment_offset}")
        print(f"Time to live: {time_to_live}")
        print(f"Protocol: {protocol}")
        print(f"Checksum: {checksum}")
        print(f"Source address: {source_address_readable}")
        print(f"Destination address: {destination_address_readable}")

    def _parse_arp_header(self, hex_data):
        # ARP header is the 14 bytes (28 hex characters) after the ethernet header
        hardware_type =  hex_data[28:32]
        protocol_type = hex_data[32:36]
        hardware_size = hex_data[36:38]
        protocol_size = hex_data[38:40]
        opcode = hex_data[40:44]
        sender_mac_address = hex_data[44:56]
        sender_ip_address = hex_data[56:64]
        target_mac_address = hex_data[64:76]
        target_ip_address = hex_data[76:84]

        # Convert from hexadecimal into decimal
        hardware_type = int(hardware_type, 16)
        hardware_size = int(hardware_size, 16)
        protocol_size = int(protocol_size, 16)
        opcode = int(opcode, 16)

        # Convert hex MAC addresses into readable format
        sender_mac_address_readable = ':'.join(sender_mac_address[i:i+2] for i in range(0, 12, 2))
        target_mac_address_readable = ':'.join(target_mac_address[i:i+2] for i in range(0, 12, 2))

        # Convert hex IP addresses into readable format
        sender_ip_address_bytes_list = ["".join(sender_ip_address)[i:i+2] for i in range(0, 8, 2)]
        sender_ip_address_bytes_list = [int(x, 16) for x in sender_ip_address_bytes_list]
        sender_ip_address_readable = ".".join(str(x) for x in sender_ip_address_bytes_list)
        target_ip_address_bytes_list = ["".join(target_ip_address)[i:i+2] for i in range(0, 8, 2)]
        target_ip_address_bytes_list = [int(x, 16) for x in target_ip_address_bytes_list]
        target_ip_address_readable = ".".join(str(x) for x in target_ip_address_bytes_list)

        print(f"Hardware type: {hardware_type} (Ethernet)")
        print(f"Protocol type: 0x{protocol_type} (IPv4)")
        print(f"Hardware size: {hardware_size}")
        print(f"Protocol size: {protocol_size}")
        if opcode == 1:
            print(f"Opcode: {opcode} (Request)")
        else:
            print(f"Opcode: {opcode} (Reply)")
        print(f"Sender MAC: {sender_mac_address_readable}")
        print(f"Sender IP: {sender_ip_address_readable}")
        print(f"Target MAC: {target_mac_address_readable}")
        print(f"Target IP: {target_ip_address_readable}")

    def _parse_header(self, hex_data):
        # Selects the header function to go down to
        completed = False
        words = self.capture_filter.split()
        for word in words:
            if word.casefold() == "arp":
                self._parse_arp_header(hex_data)
                completed = True
                break
            elif word.casefold() == "ip":
                self._parse_ipv4_header(hex_data)
                completed = True
                break
            elif word.casefold() == "tcp":
                self._parse_tcp_header(hex_data)
                completed = True
                break
            elif word.casefold() == "udp":
                self._parse_udp_header(hex_data)
                completed = True
                break
        if completed == False:
            raise RuntimeError("Filter doesn't match")
        
    def _packet_callback(self, packet):
        # Convert the raw packet to hex format
        raw_data = bytes(packet)
        hex_data = raw_data.hex()

        # Process the header
        print(f"Captured Packet (Hex): {hex_data}")
        self._parse_header(hex_data)

    # Capture packets on a specified interface using a custom filter
    def capture_packets(self):
        print(f"Starting packet capture on {self.interface} with filter: {self.capture_filter}")
        sniff(iface=self.interface, filter=self.capture_filter,  prn=self._packet_callback, count=self.packet_count)
    