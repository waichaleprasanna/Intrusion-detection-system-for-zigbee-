$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$env:Z2M_MQTT_HOST = '127.0.0.1'
$env:Z2M_MQTT_PORT = '1883'
$env:Z2M_BASE_TOPIC = 'zigbee2mqtt'
$env:Z2M_DEVICE = 'temp_sensor-1'

python app.py