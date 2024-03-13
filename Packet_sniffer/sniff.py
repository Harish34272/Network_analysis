from scapy.all import sniff

# Sniff the packets
capture = sniff(count=10)  # Adjust 'count' as needed

# Print the captured packets
for packet in capture:
    print(packet.summary())
