# Sniffer firmware

CC2531 USB dongles running TI packet-sniffer firmware are used to capture IEEE 802.15.4 / Zigbee traffic.
Captured frames are passed to Wireshark through the TI Wireshark Packet Converter pipe and to `src/sniffer.py`.

- Hardware: CC2531 dongle + CC Debugger
- Firmware file: _add the filename here_
- Source: _add the download link and version here_
- SHA-256: `921fc9e34f3776fe8cacdadf6e4da11456cbe0074f10d4ceab117f3032adda74`

Flash with SmartRF Flash Programmer exactly as described in `../coordinator/README.md`.
