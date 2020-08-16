# nweye
## Network Activity Analyzer

Captures traffic using an interface in promiscuous mode and dumpcap. The raw dumpcap output is converted into hex format and piped into decap.c which extracts certain fields from the captured data. These fields can then be piped into input_netflow which converts these fields into netflow v9 format and sends them via UDP to an ingest server.

## Captured Fields
- Frame Number: This number increments by 1 for each captured frame.
- Time (high): This is the “Timestamp (high)” field of the Enhanced Packet Block.
- Time (low): This is the “Timestamp (low)” field of the Enhanced Packet Block.
- Source MAC (high): This is the higher 3 byte portion of the Source MAC address.
- Source MAC (low): This is the lower 3 byte portion of the Source MAC address.
- Destination MAC (high): This is the higher 3 byte portion of the Destination MAC address.
- Destination MAC (low): This is the lower 3 byte portion of the Destination MAC address.
- Network Layer Protocol: In this application due to time constraints this is always IPv4.
- Source IP: This is the IP address of the sender.
- Destination IP: This is the IP address of the receiver.
- Packet Identification: This is the “Identification” field of IPv4 header.
- Transport Layer Protocols: In this application due to time constraints this is either TCP/UDP/ICMP.
- Source Port: This is the source port.
- Destination Port: the is the destination port.
- Message Length: This is the length of the message (Application Layer PDU)
- HTTP Hostname: This is used for the analysis phase explored in later sections, it is populated only if the message
is using the HTTP protocol, else it is zero.
- HTTP Get request: This is used for the analysis phase explored in later sections, it is populated only if the
message is using the HTTP protocol, else it is zero.
- Suspiciousness Level: This field is always zero, it is populated by the analysis phase explored in later sections.

## Running 

dumpcap -i <interface> -w -| xxd -p| ./decap | ./netflowv9_builder
