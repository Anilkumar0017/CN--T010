from scapy.all import rdpcap, TCP, IP
import hashlib

from ja3s_database import JA3S_FINGERPRINTS


PCAP_FILE = "captures/traffic.pcap"


print("====================================")
print("       TLS PCAP JA3S ANALYZER")
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
# PARSE SERVERHELLO
# ----------------------------------------------

def parse_server_hello(payload):

    # TLS record header:
    #
    # Byte 0     = Content Type
    # Bytes 1-2  = TLS Record Version
    # Bytes 3-4  = Record Length
    #
    # Handshake:
    #
    # Byte 5     = Handshake Type
    # Bytes 6-8  = Handshake Length
    #
    # ServerHello body:
    #
    # Bytes 9-10  = Server Version
    # Bytes 11-42 = Random
    # Byte 43     = Session ID Length
    #
    # After Session ID:
    # 2 bytes = Cipher Suite
    # 1 byte  = Compression Method
    # 2 bytes = Extensions Length
    # Extensions follow

    if len(payload) < 44:
        return None


    # TLS Handshake record

    if payload[0] != 0x16:
        return None


    # ServerHello handshake type

    if payload[5] != 0x02:
        return None


    # ------------------------------------------
    # SERVER VERSION
    # ------------------------------------------

    version = int.from_bytes(
        payload[9:11],
        byteorder="big"
    )


    # ------------------------------------------
    # SESSION ID
    # ------------------------------------------

    session_id_length = payload[43]

    position = 44 + session_id_length


    if len(payload) < position + 3:
        return None


    # ------------------------------------------
    # SELECTED CIPHER
    # ------------------------------------------

    cipher = int.from_bytes(
        payload[position:position + 2],
        byteorder="big"
    )

    position += 2


    # ------------------------------------------
    # COMPRESSION METHOD
    # ------------------------------------------

    position += 1


    # ------------------------------------------
    # EXTENSIONS
    # ------------------------------------------

    extensions = []


    if len(payload) < position + 2:
        return (
            version,
            cipher,
            extensions
        )


    extensions_length = int.from_bytes(
        payload[position:position + 2],
        byteorder="big"
    )

    position += 2


    extensions_end = position + extensions_length


    if extensions_end > len(payload):
        extensions_end = len(payload)


    while position + 4 <= extensions_end:

        extension_type = int.from_bytes(
            payload[position:position + 2],
            byteorder="big"
        )

        extension_length = int.from_bytes(
            payload[position + 2:position + 4],
            byteorder="big"
        )


        extensions.append(
            extension_type
        )


        position += 4 + extension_length


    return (
        version,
        cipher,
        extensions
    )


# ----------------------------------------------
# SEARCH PACKETS
# ----------------------------------------------

found = False


for packet_number, packet in enumerate(
    packets,
    start=1
):

    if not packet.haslayer(IP):
        continue


    if not packet.haslayer(TCP):
        continue


    # Server → Client

    if packet[TCP].sport != 443:
        continue


    payload = bytes(
        packet[TCP].payload
    )


    if len(payload) < 6:
        continue


    # TLS handshake record

    if payload[0] != 0x16:
        continue


    # ServerHello

    if payload[5] != 0x02:
        continue


    print(
        "Possible ServerHello found in packet:",
        packet_number
    )


    result = parse_server_hello(
        payload
    )


    if result is None:
        continue


    version, cipher, extensions = result


    found = True


    # ------------------------------------------
    # DISPLAY SERVERHELLO
    # ------------------------------------------

    print()

    print("====================================")
    print("       TLS SERVER HELLO FOUND")
    print("====================================")
    print()


    print("TLS Version:")
    print(version)
    print()


    print("Selected Cipher:")
    print(cipher)
    print()


    print("Extensions:")
    print(extensions)
    print()


    # ------------------------------------------
    # JA3S STRING
    # ------------------------------------------

    extension_string = "-".join(
        str(x)
        for x in extensions
    )


    ja3s_string = (
        f"{version},"
        f"{cipher},"
        f"{extension_string}"
    )


    # ------------------------------------------
    # JA3S HASH
    # ------------------------------------------

    ja3s_hash = hashlib.md5(
        ja3s_string.encode()
    ).hexdigest()


    print("====================================")
    print("             JA3S RESULT")
    print("====================================")
    print()


    print("JA3S String:")
    print(ja3s_string)
    print()


    print("JA3S Hash:")
    print(ja3s_hash)
    print()


    # ------------------------------------------
    # DATABASE LOOKUP
    # ------------------------------------------

    fingerprint = JA3S_FINGERPRINTS.get(
        ja3s_hash
    )


    print("====================================")
    print("       SERVER IDENTIFICATION")
    print("====================================")
    print()


    if fingerprint:

        print(
            "Server  :",
            fingerprint.get(
                "server",
                "Unknown"
            )
        )

        print(
            "Version :",
            fingerprint.get(
                "version",
                "Unknown"
            )
        )

        print(
            "Notes   :",
            fingerprint.get(
                "notes",
                ""
            )
        )

    else:

        print(
            "Server  : Unknown"
        )

        print(
            "Version : Unknown"
        )

        print(
            "Notes   : JA3S fingerprint not in database."
        )


    print()
    print("====================================")
    print()
    print("Analysis completed.")

    break


# ----------------------------------------------
# NO SERVERHELLO
# ----------------------------------------------

if not found:

    print()
    print("No ServerHello message was successfully parsed.")
    print()
    print("Analysis completed.")