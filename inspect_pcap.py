from scapy.all import rdpcap, IP, TCP


PCAP_FILE = "captures/traffic.pcap"


print("====================================")
print("       PCAP PACKET INSPECTOR")
print("====================================")
print()


try:

    packets = rdpcap(PCAP_FILE)

except FileNotFoundError:

    print("ERROR: traffic.pcap was not found.")
    print()
    print("Expected location:")
    print(PCAP_FILE)
    exit()


print("Total packets:", len(packets))
print()


for i, packet in enumerate(
    packets,
    start=1
):

    print("------------------------------------")
    print("Packet:", i)

    if packet.haslayer(IP):

        print(
            "Source IP       :",
            packet[IP].src
        )

        print(
            "Destination IP  :",
            packet[IP].dst
        )


    if packet.haslayer(TCP):

        print(
            "Source Port     :",
            packet[TCP].sport
        )

        print(
            "Destination Port:",
            packet[TCP].dport
        )

        print(
            "TCP Flags       :",
            packet[TCP].flags
        )

        print(
            "Sequence        :",
            packet[TCP].seq
        )

        print(
            "Payload length  :",
            len(packet[TCP].payload)
        )


        if len(packet[TCP].payload) > 0:

            payload = bytes(
                packet[TCP].payload
            )

            print(
                "First bytes     :",
                payload[:30].hex()
            )


            if payload[0] == 0x16:

                print(
                    "TLS Handshake   : YES"
                )

            elif payload[0] == 0x17:

                print(
                    "TLS Application : YES"
                )

            else:

                print(
                    "TLS record      : NO"
                )


    print()