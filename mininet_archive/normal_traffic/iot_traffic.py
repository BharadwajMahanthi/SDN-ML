#!/usr/bin/env python3
"""
IoT Sensor Traffic Generator
Simulates periodic sensor data uploads (temperature, humidity, etc.)
Represents normal IoT device behavior
"""

import time
import random
import json
from scapy.all import *

def generate_sensor_data():
    """Generate fake sensor readings"""
    return {
        "temperature": round(random.uniform(20.0, 30.0), 2),
        "humidity": round(random.uniform(30.0, 70.0), 2),
        "pressure": round(random.uniform(980.0, 1020.0), 2),
       "timestamp": int(time.time())
    }

def send_sensor_packet(sensor_ip, gateway_ip, sensor_id):
    """
    Send sensor data to gateway
    
    Args:
        sensor_ip: IoT sensor IP address
        gateway_ip: Gateway/server IP
        sensor_id: Unique sensor identifier
    """
    # Generate sensor data
    data = generate_sensor_data()
    data['sensor_id'] = sensor_id
    
    # Create UDP packet with JSON payload (common for IoT)
    payload = json.dumps(data)
    
    pkt = IP(src=sensor_ip, dst=gateway_ip) / UDP(sport=random.randint(1024, 65535), dport=8080) / Raw(load=payload)
    
    send(pkt, verbose=False)

def simulate_iot_network(sensors, gateway="10.0.0.6", interval=5, duration=60):
    """
    Simulate IoT sensor network
    
    Args:
        sensors: List of (sensor_ip, sensor_id) tuples
        gateway: Gateway server IP
        interval: Upload interval in seconds
        duration: Total simulation time
    """
    print(f"[*] Simulating IoT Sensor Network")
    print(f"[*] Sensors: {len(sensors)}")
    print(f"[*] Gateway: {gateway}")
    print(f"[*] Upload interval: {interval} seconds")
    print(f"[*] Duration: {duration} seconds")
    
    start_time = time.time()
    upload_count = 0
    
    while (time.time() - start_time) < duration:
        # All sensors upload at roughly the same time
        for sensor_ip, sensor_id in sensors:
            send_sensor_packet(sensor_ip, gateway, sensor_id)
            upload_count += 1
        
        print(f"[+] Upload cycle completed: {upload_count} total readings")
        
        # Wait for next upload cycle
        time.sleep(interval)
    
    print(f"[✓] IoT simulation completed: {upload_count} sensor readings sent")

if __name__ == "__main__":
    # Define IoT sensors
    iot_sensors = [
        ("10.0.0.1", "sensor_temp_01"),
        ("10.0.0.2", "sensor_humid_01"),
        ("10.0.0.3", "sensor_pressure_01"),
        ("10.0.0.4", "sensor_temp_02"),
        ("10.0.0.5", "sensor_humid_02"),
    ]
    
    try:
        simulate_iot_network(iot_sensors, interval=10, duration=120)
    except PermissionError:
        print("[!] Error: Requires root/administrator privileges")
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
    except Exception as e:
        print(f"[!] Error: {e}")
