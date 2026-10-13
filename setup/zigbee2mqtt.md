# Zigbee2MQTT setup (Windows)

1. Install the CP210x driver; the ZBDongle-E appears as **COM4**.
2. Install Mosquitto and start the broker.
3. Install Zigbee2MQTT 2.14.1 and set in `configuration.yaml`:
   - serial port `COM4`, adapter `ember`
   - channel `15`
   - frontend on port `8080`
4. Start Zigbee2MQTT, enable pairing, and join the SNZB-02D (rename it `temp_sensor-1`).
