from scapy.all import rdpcap, IP, TCP
from scapy.layers.tls.all import TLS, TLSClientHello

from fingerprint.ja3 import calculate_ja3
from fingerprint_database import FINGERPRINTS
from save_ja3 import save_ja3


print("====================================")
print("       TLS PCAP JA3 ANALYZER")
print("====================================")
print()


# ------------------------------------------
# LOAD PCAP
# ------------------------------------------

try:
    packets = rdpcap("traffic.pcap")

except FileNotFoundError:
    print("ERROR: traffic.pcap was not found.")
    exit()


print("Packets loaded:", len(packets))
print()


# ------------------------------------------
# COUNTERS
# ------------------------------------------

client_hello_count = 0
known_count = 0
unknown_count = 0

seen_fingerprints = set()


# ------------------------------------------
# SCAN ALL PACKETS
# ------------------------------------------

for packet_number, packet in enumerate(
    packets,
    start=1
):

    # Must contain TCP
    if not packet.haslayer(TCP):
        continue

    # Client → Server HTTPS traffic
    if packet[TCP].dport != 443:
        continue

    # Must contain payload
    if len(packet[TCP].payload) == 0:
        continue

    payload = bytes(packet[TCP].payload)

    # TLS record must contain enough bytes
    if len(payload) < 6:
        continue

    # TLS Handshake record
    if payload[0] != 0x16:
        continue

    # ClientHello handshake
    if payload[5] != 0x01:
        continue


    # ------------------------------------------
    # PARSE TLS
    # ------------------------------------------

    try:
        tls_packet = TLS(payload)

    except Exception:
        continue


    if not tls_packet.haslayer(TLSClientHello):
        continue


    client_hello_count += 1

    client_hello = tls_packet[TLSClientHello]


    # ------------------------------------------
    # BASIC CONNECTION INFORMATION
    # ------------------------------------------

    source_ip = "Unknown"
    destination_ip = "Unknown"

    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

    source_port = packet[TCP].sport
    destination_port = packet[TCP].dport


    # ------------------------------------------
    # TLS VERSION
    # ------------------------------------------

    version = int(client_hello.version)


    # ------------------------------------------
    # CIPHER SUITES
    # ------------------------------------------

    ciphers = []

    if client_hello.ciphers:

        for cipher in client_hello.ciphers:

            try:
                ciphers.append(int(cipher))

            except Exception:
                pass


    # ------------------------------------------
    # EXTENSIONS
    # ------------------------------------------

    extensions = []

    if client_hello.ext is not None:

        for extension in client_hello.ext:

            if hasattr(extension, "type"):

                try:
                    extensions.append(
                        int(extension.type)
                    )

                except Exception:
                    pass


    # ------------------------------------------
    # SUPPORTED GROUPS
    # ------------------------------------------

    groups = []

    if client_hello.ext is not None:

        for extension in client_hello.ext:

            if hasattr(extension, "groups"):

                try:

                    groups.extend(
                        int(group)
                        for group in extension.groups
                    )

                except Exception:
                    pass


    # ------------------------------------------
    # EC POINT FORMATS
    # ------------------------------------------

    point_formats = []

    if client_hello.ext is not None:

        for extension in client_hello.ext:

            if hasattr(extension, "ecpl"):

                try:

                    point_formats.extend(
                        int(value)
                        for value in extension.ecpl
                    )

                except Exception:
                    pass


    # ------------------------------------------
    # CALCULATE JA3
    # ------------------------------------------

    ja3_string, ja3_hash = calculate_ja3(
        version,
        ciphers,
        extensions,
        groups,
        point_formats
    )


    # ------------------------------------------
    # REMOVE DUPLICATE FINGERPRINTS
    # ------------------------------------------

    if ja3_hash in seen_fingerprints:
        continue

    seen_fingerprints.add(ja3_hash)


    # ------------------------------------------
    # DATABASE LOOKUP
    # ------------------------------------------

    fingerprint = FINGERPRINTS.get(
        ja3_hash
    )


    if fingerprint:

        application = fingerprint.get(
            "application",
            "Unknown"
        )

        client_version = fingerprint.get(
            "version",
            "Unknown"
        )

        tls_stack = fingerprint.get(
            "tls_stack",
            "Unknown"
        )

        notes = fingerprint.get(
            "notes",
            ""
        )

        known_count += 1

    else:

        application = "Unknown"

        client_version = "Unknown"

        tls_stack = "Unknown"

        notes = "Fingerprint not in database."

        unknown_count += 1


    # ------------------------------------------
    # DISPLAY RESULT
    # ------------------------------------------

    print("====================================")
    print(
        "       CLIENT HELLO FOUND"
    )
    print("====================================")

    print()

    print(
        "Packet number :",
        packet_number
    )

    print(
        "Source        :",
        source_ip
    )

    print(
        "Destination   :",
        destination_ip
    )

    print(
        "Source port   :",
        source_port
    )

    print(
        "Dest port     :",
        destination_port
    )

    print()

    print(
        "TLS Version   :",
        version
    )

    print()

    print(
        "JA3 String:"
    )

    print(ja3_string)

    print()

    print(
        "JA3 Hash:"
    )

    print(ja3_hash)

    print()

    print(
        "Application :",
        application
    )

    print(
        "Version     :",
        client_version
    )

    print(
        "TLS Stack   :",
        tls_stack
    )

    print(
        "Notes       :",
        notes
    )

    print()


    # ------------------------------------------
    # SAVE TO CSV
    # ------------------------------------------

    save_ja3(
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        version,
        ja3_string,
        ja3_hash,
        application,
        client_version,
        tls_stack
    )


# ------------------------------------------
# FINAL SUMMARY
# ------------------------------------------

print()
print("====================================")
print("          JA3 ANALYSIS SUMMARY")
print("====================================")

print()

print(
    "ClientHello packets found :",
    client_hello_count
)

print(
    "Unique fingerprints       :",
    len(seen_fingerprints)
)

print(
    "Known fingerprints        :",
    known_count
)

print(
    "Unknown fingerprints      :",
    unknown_count
)

print()

print(
    "JA3 analysis completed."
)

print("====================================")