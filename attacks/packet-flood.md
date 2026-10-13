# Packet flood
**What:** a device or attacker sends an abnormally high number of frames in a short time.
**Detection:** the engine counts packets over a time window and raises an alert when the rate crosses its threshold.
**Evidence:** `screenshots/dashboard/packet-flooding-detection-off.png` and `packet-flooding-detection-on.png`.
**Try it:** trigger the flood from `attack_tool.py` with detection OFF, then ON.
> Check the threshold and window values in `src/engine.py` and add them here.
