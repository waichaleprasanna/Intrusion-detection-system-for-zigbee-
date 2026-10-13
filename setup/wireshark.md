# Wireshark live capture

1. Flash a CC2531 with sniffer firmware (see `firmware/sniffer/`).
2. Run the TI Wireshark Packet Converter so it exposes the dongle as a pipe.
3. In Wireshark add that pipe as an interface and capture on channel 15.
4. Zigbee frames from the network appear live.
