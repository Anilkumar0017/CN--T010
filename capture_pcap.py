from scapy.all import sniff, wrpcap
import os


PCAP_FILE = "captures/traffic.pcap"


print("====================================")
print("       TLS PACKET CAPTURE")
print("====================================")
print()
print("Capturing TCP port 443 traffic...")
print("The capture will run for 30 seconds.")
print()
print("Run your controlled HTTPS test in another PowerShell window.")
print()


packets = sniff(
    filter="tcp port 443",
    timeout=30,
    store=True
)


print()
print("====================================")
print("Capture completed")
print("Packets captured:", len(packets))
print("====================================")


if packets:

    os.makedirs("captures", exist_ok=True)

    wrpcap(
        PCAP_FILE,
        packets
    )

    print()
    print("Saved as:", PCAP_FILE)

else:

    print()
    print("No packets captured.")