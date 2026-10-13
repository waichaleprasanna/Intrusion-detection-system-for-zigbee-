# Hardware

| Device | Role | Notes |
|---|---|---|
| CC2531 USB dongle (counterfeit, 128 KB flash) | Sniffer | Only sniffer firmware fits |
| CC Debugger | Flashing | Used with SmartRF Flash Programmer |
| Sonoff ZBDongle-E | Coordinator | EmberZNet, CP210x driver, COM4 |
| Sonoff SNZB-02D | Test end device | Named `temp_sensor-1` in Zigbee2MQTT |

See `firmware/` for flashing steps.
