from scapy.all import rdpcap, TCP, IP
import hashlib

from fingerprint_database import FINGERPRINTS
from ja3s_database import JA3S_FINGERPRINTS


PCAP_FILE = "captures/traffic.pcap"


print("====================================")
print("       JA3 + JA3S FLOW CORRELATION")
print("====================================")
print()


# ----------------------------------------------
# LOAD PCAP
# ----------------------------------------------

try:

    packets = rdpcap(PCAP_FILE)

except FileNotFoundError:

    print("ERROR: traffic.pcap was not found.")
    print()
    print("Expected location:")
    print(PCAP_FILE)
    exit()


print("Packets loaded:", len(packets))
print()


# ----------------------------------------------
# TLS PARSING FUNCTIONS
# ----------------------------------------------

def parse_client_hello(payload):

    if len(payload) < 6:
        return None

    if payload[0] != 0x16:
        return None

    if payload[5] != 0x01:
        return None

    # Need enough data for TLS ClientHello
    if len(payload) < 43:
        return None

    try:

        version = int.from_bytes(
            payload[9:11],
            byteorder="big"
        )

        position = 43

        session_id_length = payload[position]

        position += 1 + session_id_length

        if position + 2 > len(payload):
            return None

        cipher_length = int.from_bytes(
            payload[position:position + 2],
            byteorder="big"
        )

        position += 2

        cipher_end = position + cipher_length

        if cipher_end > len(payload):
            return None

        cipher_suites = []

        while position + 2 <= cipher_end:

            cipher = int.from_bytes(
                payload[position:position + 2],
                byteorder="big"
            )

            cipher_suites.append(cipher)

            position += 2

        if position >= len(payload):
            return None

        compression_length = payload[position]

        position += 1 + compression_length

        if position + 2 > len(payload):
            return None

        extension_length = int.from_bytes(
            payload[position:position + 2],
            byteorder="big"
        )

        position += 2

        extension_end = position + extension_length

        if extension_end > len(payload):
            extension_end = len(payload)

        extensions = []
        supported_groups = []
        ec_point_formats = []

        while position + 4 <= extension_end:

            extension_type = int.from_bytes(
                payload[position:position + 2],
                byteorder="big"
            )

            extension_size = int.from_bytes(
                payload[position + 2:position + 4],
                byteorder="big"
            )

            extension_data_start = position + 4
            extension_data_end = (
                extension_data_start + extension_size
            )

            if extension_data_end > extension_end:
                break

            extensions.append(extension_type)

            # Supported Groups extension
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

                    while group_position + 2 <= group_end:

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

            # EC Point Formats extension
            elif extension_type == 11:

                data = payload[
                    extension_data_start:
                    extension_data_end
                ]

                if len(data) >= 1:

                    format_length = data[0]

                    for value in data[
                        1:
                        min(
                            1 + format_length,
                            len(data)
                        )
                    ]:

                        ec_point_formats.append(
                            value
                        )

            position = extension_data_end

        return (
            version,
            cipher_suites,
            extensions,
            supported_groups,
            ec_point_formats
        )

    except Exception:

        return None


def parse_server_hello(payload):

    if len(payload) < 44:
        return None

    if payload[0] != 0x16:
        return None

    if payload[5] != 0x02:
        return None

    try:

        version = int.from_bytes(
            payload[9:11],
            byteorder="big"
        )

        session_id_length = payload[43]

        position = 44 + session_id_length

        if position + 3 > len(payload):
            return None

        cipher = int.from_bytes(
            payload[position:position + 2],
            byteorder="big"
        )

        position += 3

        extensions = []

        if position + 2 <= len(payload):

            extensions_length = int.from_bytes(
                payload[position:position + 2],
                byteorder="big"
            )

            position += 2

            extensions_end = min(
                position + extensions_length,
                len(payload)
            )

            while position + 4 <= extensions_end:

                extension_type = int.from_bytes(
                    payload[position:position + 2],
                    byteorder="big"
                )

                extension_size = int.from_bytes(
                    payload[position + 2:position + 4],
                    byteorder="big"
                )

                extensions.append(
                    extension_type
                )

                position += 4 + extension_size

        return (
            version,
            cipher,
            extensions
        )

    except Exception:

        return None


def calculate_ja3(
    version,
    cipher_suites,
    extensions,
    supported_groups,
    ec_point_formats
):

    def is_grease(value):

        return (
            value & 0x0F0F
        ) == 0x0A0A


    cipher_suites = [
        value
        for value in cipher_suites
        if not is_grease(value)
    ]

    extensions = [
        value
        for value in extensions
        if not is_grease(value)
    ]

    supported_groups = [
        value
        for value in supported_groups
        if not is_grease(value)
    ]


    cipher_string = "-".join(
        str(value)
        for value in cipher_suites
    )

    extension_string = "-".join(
        str(value)
        for value in extensions
    )

    group_string = "-".join(
        str(value)
        for value in supported_groups
    )

    point_string = "-".join(
        str(value)
        for value in ec_point_formats
    )


    ja3_string = (
        f"{version},"
        f"{cipher_string},"
        f"{extension_string},"
        f"{group_string},"
        f"{point_string}"
    )


    ja3_hash = hashlib.md5(
        ja3_string.encode()
    ).hexdigest()


    return ja3_string, ja3_hash


def calculate_ja3s(
    version,
    cipher,
    extensions
):

    extension_string = "-".join(
        str(value)
        for value in extensions
    )

    ja3s_string = (
        f"{version},"
        f"{cipher},"
        f"{extension_string}"
    )

    ja3s_hash = hashlib.md5(
        ja3s_string.encode()
    ).hexdigest()

    return ja3s_string, ja3s_hash


# ----------------------------------------------
# BUILD TCP STREAMS
# ----------------------------------------------

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


    key = (
        source_ip,
        source_port,
        destination_ip,
        destination_port
    )


    if key not in streams:

        streams[key] = []


    streams[key].append(
        (
            tcp.seq,
            payload
        )
    )


# ----------------------------------------------
# REASSEMBLE STREAMS
# ----------------------------------------------

def reassemble(segments):

    segments = sorted(
        segments,
        key=lambda item: item[0]
    )


    stream = bytearray()

    next_sequence = None


    for sequence, payload in segments:

        if next_sequence is None:

            stream.extend(payload)

            next_sequence = (
                sequence + len(payload)
            )

            continue


        if sequence >= next_sequence:

            gap = sequence - next_sequence

            if gap > 0:

                # Cannot reconstruct across a gap
                continue

            stream.extend(payload)

            next_sequence = (
                sequence + len(payload)
            )

        else:

            overlap = (
                next_sequence - sequence
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


# ----------------------------------------------
# FIND JA3 AND JA3S PER CONNECTION
# ----------------------------------------------

connections = {}


for key, segments in streams.items():

    source_ip, source_port, destination_ip, destination_port = key


    stream = reassemble(
        segments
    )


    if not stream:
        continue


    # Client → Server

    if destination_port == 443:

        parsed = parse_client_hello(
            stream
        )

        if parsed:

            (
                version,
                cipher_suites,
                extensions,
                supported_groups,
                ec_point_formats
            ) = parsed


            ja3_string, ja3_hash = calculate_ja3(
                version,
                cipher_suites,
                extensions,
                supported_groups,
                ec_point_formats
            )


            flow_key = (
                source_ip,
                source_port,
                destination_ip,
                destination_port
            )


            connections[
                flow_key
            ] = {

                "client_ip": source_ip,
                "client_port": source_port,
                "server_ip": destination_ip,
                "server_port": destination_port,

                "ja3_string": ja3_string,
                "ja3_hash": ja3_hash,

                "ja3s_string": None,
                "ja3s_hash": None
            }


# ----------------------------------------------
# SERVER → CLIENT JA3S
# ----------------------------------------------

for key, segments in streams.items():

    source_ip, source_port, destination_ip, destination_port = key


    if source_port != 443:
        continue


    stream = reassemble(
        segments
    )


    if not stream:
        continue


    parsed = parse_server_hello(
        stream
    )


    if not parsed:
        continue


    version, cipher, extensions = parsed


    ja3s_string, ja3s_hash = calculate_ja3s(
        version,
        cipher,
        extensions
    )


    matching_flow = (
        destination_ip,
        destination_port,
        source_ip,
        source_port
    )


    if matching_flow in connections:

        connections[
            matching_flow
        ]["ja3s_string"] = ja3s_string

        connections[
            matching_flow
        ]["ja3s_hash"] = ja3s_hash


# ----------------------------------------------
# DISPLAY RESULTS
# ----------------------------------------------

print()
print("====================================")
print("       TLS CONNECTION PROFILES")
print("====================================")
print()


connection_number = 0


for flow_key, profile in connections.items():

    connection_number += 1


    ja3_hash = profile[
        "ja3_hash"
    ]

    ja3s_hash = profile[
        "ja3s_hash"
    ]


    client_fingerprint = FINGERPRINTS.get(
        ja3_hash
    )


    server_fingerprint = None


    if ja3s_hash:

        server_fingerprint = JA3S_FINGERPRINTS.get(
            ja3s_hash
        )


    print("------------------------------------")

    print(
        "Connection:",
        connection_number
    )

    print()

    print(
        "Client:",
        f"{profile['client_ip']}:{profile['client_port']}"
    )

    print(
        "Server:",
        f"{profile['server_ip']}:{profile['server_port']}"
    )

    print()


    # Client

    if client_fingerprint:

        print(
            "Client Application :",
            client_fingerprint.get(
                "application",
                "Unknown"
            )
        )

        print(
            "Client Status      : KNOWN"
        )

    else:

        print(
            "Client Application : Unknown"
        )

        print(
            "Client Status      : UNKNOWN"
        )


    print(
        "Client JA3         :",
        ja3_hash
    )

    print()


    # Server

    if server_fingerprint:

        print(
            "Server             :",
            server_fingerprint.get(
                "server",
                "Unknown"
            )
        )

        print(
            "Server Status      : KNOWN"
        )

    else:

        print(
            "Server             : Unknown"
        )

        print(
            "Server Status      : UNKNOWN"
        )


    if ja3s_hash:

        print(
            "Server JA3S        :",
            ja3s_hash
        )

    else:

        print(
            "Server JA3S        : Not found"
        )


print()
print("====================================")
print("TLS flow correlation completed.")
print(
    "Connections found:",
    connection_number
)
print("====================================")