# Coordinator firmware

| Item | Value |
|---|---|
| File | `CC2531ZNP-Prod.hex` |
| Type | TI Z-Stack ZNP (Zigbee Network Processor) coordinator firmware |
| Target chip | TI CC2531 USB dongle |
| Format | Intel HEX |
| Size | 697,099 bytes |
| SHA-256 | `42092c74d817acdca4fecf2b6a3c13fe17c27039203a17da722e38153efa6247` |

Verify on Windows: `certutil -hashfile CC2531ZNP-Prod.hex SHA256`
Verify on Linux/macOS: `sha256sum CC2531ZNP-Prod.hex`

## Flashing
Flash with a **CC Debugger** and TI **SmartRF Flash Programmer** (or `cc-tool`):
1. Connect the CC Debugger to the CC2531 debug pins and to the PC.
2. Open SmartRF Flash Programmer, select the CC2531 target.
3. Load `CC2531ZNP-Prod.hex`, choose *Erase, program and verify*, then flash.

## Important notes
- This image is for a **genuine CC2531** with a full-size flash. It will not fit the counterfeit 128 KB CC2531 clones, which are only usable with sniffer firmware.
- It is **not** for the Sonoff ZBDongle-E. That dongle runs EmberZNet firmware and is the coordinator used with Zigbee2MQTT in this project (COM4, channel 15).
- Included as a reference for the CC2531 coordinator option. Check the licence of the TI / Z-Stack-based source before redistributing.
