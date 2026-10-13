# External tools (not installed with pip)

These are separate Windows programs. They are not in `requirements.txt`.

| Tool | Used for | Notes |
|---|---|---|
| **SmartRF Flash Programmer** (TI) | Flashing sniffer and coordinator firmware onto CC2531 dongles | Used with the CC Debugger. Download from TI's website |
| **CC Debugger** (hardware) | Connects the PC to the CC2531 debug pins for flashing | Needs its TI driver installed |
| **TI Wireshark Packet Converter (TIWSPC)** | Turns CC2531 sniffer output into a pipe Wireshark can read | See `wireshark.md` |
| **Wireshark** | Viewing live 802.15.4 / Zigbee frames | Add the converter's pipe as an interface |
| **Npcap** | Packet capture driver for Windows | Needed if `scapy` sniffs live traffic |
| **CP210x driver** (Silicon Labs) | Lets Windows see the Sonoff ZBDongle-E (COM4) | |
| **Mosquitto** | Local MQTT broker | Used with Zigbee2MQTT |
| **Zigbee2MQTT 2.14.1** | Runs the coordinator and pairs devices | See `zigbee2mqtt.md` |
