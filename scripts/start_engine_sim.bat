@echo off
cd /d "%~dp0"
set "ENABLE_UDP_ATTACK_STREAM=1"
python engine.py
