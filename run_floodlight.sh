#!/bin/bash
# Launch Floodlight on macOS/Linux

echo "[INFO] Starting Floodlight Controller..."
echo "[INFO] Ensure you have Java 8 or 11 installed."

cd floodlight_with_topoguard
java -jar target/floodlight.jar
