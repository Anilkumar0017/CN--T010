from scapy.all import rdpcap, TCP, IP

from fingerprint.ja3 import calculate_ja3
from fingerprint_database import FINGERPRINTS
from save_ja3 import save_ja3


# ============================================================
# CONFIGURATION
# ============================================================

PCAP_FILE = "captures/traffic.pcap"


print("==============================================")
print("          TLS PCAP JA3 ANALYZER")
print("==============================================")
print()


# ============================================================
# LOAD PCAP
# ============================================================

try:

    packets = rdpcap(PCAP_FILE)

except FileNotFoundError:

    print("ERROR: traffic.pcap was not found.")
    print()
    print("Expected location:")
    print(PCAP_FILE)
    print()

    exit()


print("Packets loaded:", len(packets))
print()


# ============================================================
# TCP STREAM STORAGE
# ============================================================

streams = {}


for packet in packets:

    if not packet.haslayer(IP):
        continue

    if not packet.haslayer(TCP):
        continue


    tcp = packet[TCP]

    payload = bytes(
        tcp.payload
    )


    if not payload:
        continue


    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    source_port = tcp.sport
    destination_port = tcp.dport


    # Only TLS client traffic going to HTTPS servers
    if destination_port != 443:
        continue


    stream_key = (
        source_ip,
        source_port,
        destination_ip,
        destination_port
    )


    if stream_key not in streams:

        streams[stream_key] = []


    streams[stream_key].append(
        (
            tcp.seq,
            payload
        )
    )


print(
    "TCP client streams found:",
    len(streams)
)

print()


# ============================================================
# TCP STREAM REASSEMBLY
# ============================================================

def reassemble_stream(segments):

    segments = sorted(
        segments,
        key=lambda item: item[0]
    )


    stream = bytearray()

    next_sequence = None


    for sequence, payload in segments:

        if next_sequence is None:

            stream.extend(
                payload
            )

            next_sequence = (
                sequence +
                len(payload)
            )

            continue


        # New data after current stream
        if sequence >= next_sequence:

            gap = sequence - next_sequence


            # Ignore incomplete gaps
            if gap > 0:

                continue


            stream.extend(
                payload
            )

            next_sequence = (
                sequence +
                len(payload)
            )

            continue


        # Retransmission / overlapping segment
        overlap = (
            next_sequence -
            sequence
        )


        if overlap < len(payload):

            new_data = payload[
                overlap:
            ]


            stream.extend(
                new_data
            )


            next_sequence += len(
                new_data
            )


    return bytes(stream)


# ============================================================
# TLS CLIENTHELLO PARSER
# ============================================================

def parse_client_hello(payload):

    # --------------------------------------------------------
    # TLS record
    #
    # Byte 0       = Content Type
    # Bytes 1-2    = TLS version
    # Bytes 3-4    = Record length
    #
    # Handshake
    #
    # Byte 5       = Handshake type
    # Bytes 6-8    = Handshake length
    #
    # ClientHello
    #
    # Bytes 9-10   = Client version
    # Bytes 11-42  = Random
    # Byte 43      = Session ID length
    # --------------------------------------------------------


    if len(payload) < 44:

        return None


    # TLS Handshake record
    if payload[0] != 0x16:

        return None


    # ClientHello handshake
    if payload[5] != 0x01:

        return None


    try:

        # TLS version
        version = int.from_bytes(
            payload[9:11],
            byteorder="big"
        )


        position = 43


        # ----------------------------------------------------
        # Session ID
        # ----------------------------------------------------

        session_id_length = payload[
            position
        ]


        position += (
            1 +
            session_id_length
        )


        if position + 2 > len(payload):

            return None


        # ----------------------------------------------------
        # Cipher Suites
        # ----------------------------------------------------

        cipher_length = int.from_bytes(
            payload[
                position:
                position + 2
            ],
            byteorder="big"
        )


        position += 2


        cipher_end = (
            position +
            cipher_length
        )


        if cipher_end > len(payload):

            return None


        cipher_suites = []


        while position + 2 <= cipher_end:

            cipher = int.from_bytes(
                payload[
                    position:
                    position + 2
                ],
                byteorder="big"
            )


            cipher_suites.append(
                cipher
            )


            position += 2


        # ----------------------------------------------------
        # Compression Methods
        # ----------------------------------------------------

        if position >= len(payload):

            return None


        compression_length = payload[
            position
        ]


        position += (
            1 +
            compression_length
        )


        if position + 2 > len(payload):

            return None


        # ----------------------------------------------------
        # Extensions
        # ----------------------------------------------------

        extension_length = int.from_bytes(
            payload[
                position:
                position + 2
            ],
            byteorder="big"
        )


        position += 2


        extension_end = (
            position +
            extension_length
        )


        if extension_end > len(payload):

            extension_end = len(
                payload
            )


        extensions = []

        supported_groups = []

        ec_point_formats = []


        # ----------------------------------------------------
        # Parse each extension
        # ----------------------------------------------------

        while position + 4 <= extension_end:

            extension_type = int.from_bytes(
                payload[
                    position:
                    position + 2
                ],
                byteorder="big"
            )


            extension_size = int.from_bytes(
                payload[
                    position + 2:
                    position + 4
                ],
                byteorder="big"
            )


            extension_data_start = (
                position +
                4
            )


            extension_data_end = (
                extension_data_start +
                extension_size
            )


            if extension_data_end > extension_end:

                break


            extensions.append(
                extension_type
            )


            # ------------------------------------------------
            # Supported Groups extension
            # Extension ID = 10
            # ------------------------------------------------

            if extension_type == 10:

                data = payload[
                    extension_data_start:
                    extension_data_end
                ]


                if len(data) >= 2:

                    groups_length = int.from_bytes(
                        data[0:2],
                        byteorder="big"
                    )


                    group_position = 2


                    group_end = min(
                        2 + groups_length,
                        len(data)
                    )


                    while (
                        group_position + 2
                        <= group_end
                    ):

                        group = int.from_bytes(
                            data[
                                group_position:
                                group_position + 2
                            ],
                            byteorder="big"
                        )


                        supported_groups.append(
                            group
                        )


                        group_position += 2


            # ------------------------------------------------
            # EC Point Formats extension
            # Extension ID = 11
            # ------------------------------------------------

            elif extension_type == 11:

                data = payload[
                    extension_data_start:
                    extension_data_end
                ]


                if len(data) >= 1:

                    format_length = data[0]


                    format_end = min(
                        1 + format_length,
                        len(data)
                    )


                    for value in data[
                        1:
                        format_end
                    ]:

                        ec_point_formats.append(
                            value
                        )


            position = (
                extension_data_end
            )


        return (
            version,
            cipher_suites,
            extensions,
            supported_groups,
            ec_point_formats
        )


    except Exception:

        return None


# ============================================================
# ANALYZE CLIENT STREAMS
# ============================================================

total_client_hellos = 0

unique_fingerprints = set()


for stream_key, segments in streams.items():

    source_ip = stream_key[0]
    source_port = stream_key[1]

    destination_ip = stream_key[2]
    destination_port = stream_key[3]


    stream = reassemble_stream(
        segments
    )


    if not stream:

        continue


    # --------------------------------------------------------
    # Find TLS ClientHello
    # --------------------------------------------------------

    parsed = None


    for offset in range(
        0,
        max(0, len(stream) - 5)
    ):

        if stream[offset] != 0x16:

            continue


        if (
            offset + 5 < len(stream)
            and stream[offset + 5] == 0x01
        ):

            parsed = parse_client_hello(
                stream[offset:]
            )


            if parsed:

                break


    if not parsed:

        continue


    (
        version,
        cipher_suites,
        extensions,
        supported_groups,
        ec_point_formats
    ) = parsed


    # --------------------------------------------------------
    # Calculate JA3
    # --------------------------------------------------------

    ja3_string, ja3_hash = calculate_ja3(
        version,
        cipher_suites,
        extensions,
        supported_groups,
        ec_point_formats
    )


    total_client_hellos += 1

    unique_fingerprints.add(
        ja3_hash
    )


    # --------------------------------------------------------
    # Fingerprint database lookup
    # --------------------------------------------------------

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


        status = "KNOWN"


    else:

        application = "Unknown"

        client_version = "Unknown"

        tls_stack = "Unknown"

        status = "UNKNOWN"


    # --------------------------------------------------------
    # Print result
    # --------------------------------------------------------

    print("----------------------------------------------")

    print(
        "Connection:",
        f"{source_ip}:{source_port}"
        " -> "
        f"{destination_ip}:{destination_port}"
    )


    print(
        "TLS Version:",
        version
    )


    print(
        "JA3:",
        ja3_hash
    )


    print(
        "Application:",
        application
    )


    print(
        "Version:",
        client_version
    )


    print(
        "TLS Stack:",
        tls_stack
    )


    print(
        "Status:",
        status
    )


    print()


    # --------------------------------------------------------
    # Save to CSV
    # --------------------------------------------------------

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


# ============================================================
# FINAL SUMMARY
# ============================================================

print()
print("==============================================")
print("             JA3 ANALYSIS SUMMARY")
print("==============================================")
print()


print(
    "ClientHello messages found:",
    total_client_hellos
)


print(
    "Unique JA3 fingerprints:",
    len(unique_fingerprints)
)


print()


print("JA3 PCAP analysis completed.")


print("==============================================")