from scapy.all import sniff, IP, TCP
from scapy.layers.tls.all import TLS, TLSClientHello

from fingerprint.ja3 import calculate_ja3


print("====================================")
print("       TLS FINGERPRINTING PROJECT")
print("====================================")
print()
print("Starting TLS packet capture...")
print("Capturing TCP port 443 traffic.")
print("Press Ctrl+C to stop.")
print()


def get_extension_data(client_hello):
    """
    Extract the numeric TLS extension IDs.
    """

    extensions = []

    if client_hello.ext is None:
        return extensions

    for extension in client_hello.ext:

        if hasattr(extension, "type"):
            extensions.append(int(extension.type))

    return extensions


def get_supported_groups(client_hello):
    """
    Extract supported elliptic curve/group IDs.
    """

    groups = []

    if client_hello.ext is None:
        return groups

    for extension in client_hello.ext:

        # Supported Groups extension
        if hasattr(extension, "groups"):

            try:
                groups.extend(
                    int(group) for group in extension.groups
                )

            except Exception:
                pass

    return groups


def get_point_formats(client_hello):
    """
    Extract EC point format IDs.
    """

    formats = []

    if client_hello.ext is None:
        return formats

    for extension in client_hello.ext:

        if hasattr(extension, "ecpl"):

            try:
                formats.extend(
                    int(value)
                    for value in extension.ecpl
                )

            except Exception:
                pass

    return formats


def packet_callback(packet):

    # We only want TCP packets
    if not packet.haslayer(TCP):
        return

    # We only want traffic going TO port 443
    if packet[TCP].dport != 443:
        return

    # Ignore packets without payload
    if len(packet[TCP].payload) == 0:
        return

    payload = bytes(packet[TCP].payload)

    # TLS Handshake record starts with 0x16
    if len(payload) < 5:
        return

    if payload[0] != 0x16:
        return

    try:

        tls_packet = TLS(payload)

    except Exception:
        return

    # Check for ClientHello
    if not tls_packet.haslayer(TLSClientHello):
        return

    client_hello = tls_packet[TLSClientHello]

    print()
    print("====================================")
    print("       TLS CLIENT HELLO FOUND")
    print("====================================")

    if packet.haslayer(IP):

        print("Source      :", packet[IP].src)
        print("Destination :", packet[IP].dst)

    print("Source port :", packet[TCP].sport)
    print("Dest port   :", packet[TCP].dport)

    # ------------------------------
    # TLS VERSION
    # ------------------------------

    version = int(client_hello.version)

    # ------------------------------
    # CIPHER SUITES
    # ------------------------------

    ciphers = []

    if client_hello.ciphers:

        for cipher in client_hello.ciphers:

            try:
                ciphers.append(int(cipher))

            except Exception:
                pass

    # ------------------------------
    # EXTENSIONS
    # ------------------------------

    extensions = get_extension_data(
        client_hello
    )

    # ------------------------------
    # SUPPORTED GROUPS
    # ------------------------------

    supported_groups = get_supported_groups(
        client_hello
    )

    # ------------------------------
    # EC POINT FORMATS
    # ------------------------------

    ec_point_formats = get_point_formats(
        client_hello
    )

    # ------------------------------
    # DISPLAY INFORMATION
    # ------------------------------

    print()
    print("TLS Version:")
    print(version)

    print()
    print("Cipher Suites:")
    print(ciphers)

    print()
    print("Extensions:")
    print(extensions)

    print()
    print("Supported Groups:")
    print(supported_groups)

    print()
    print("EC Point Formats:")
    print(ec_point_formats)

    # ------------------------------
    # CALCULATE JA3
    # ------------------------------

    try:

        ja3_string, ja3_hash = calculate_ja3(
            version,
            ciphers,
            extensions,
            supported_groups,
            ec_point_formats
        )

        print()
        print("====================================")
        print("             JA3 RESULT")
        print("====================================")

        print()
        print("JA3 String:")
        print(ja3_string)

        print()
        print("JA3 Hash:")
        print(ja3_hash)

        print()
        print("====================================")

    except Exception as e:

        print()
        print("JA3 calculation error:")
        print(e)


sniff(
    filter="tcp port 443",
    prn=packet_callback,
    store=False
)