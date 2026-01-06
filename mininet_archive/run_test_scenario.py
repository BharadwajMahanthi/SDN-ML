import time
import sys
import os
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import SingleSwitchTopo
from mininet.log import setLogLevel, info
from functools import partial

def run_scenario():
    setLogLevel('info')
    
    # Configuration
    CONTROLLER_IP = '127.0.0.1' 
    CONTROLLER_PORT = 6653
    
    info('*** Connecting to Floodlight at %s:%d\n' % (CONTROLLER_IP, CONTROLLER_PORT))

    topo = SingleSwitchTopo(k=4)
    # Use Userspace OVS for Docker compatibility
    net = Mininet(topo=topo, 
                  controller=None, 
                  switch=partial(OVSSwitch, datapath='user'))

    # Add Remote Controller
    c0 = RemoteController('c0', ip=CONTROLLER_IP, port=CONTROLLER_PORT)
    net.addController(c0)

    try:
        net.start()
        info('*** Waiting for switch to connect to controller...\n')
        # Wait 10s for userspace switch to initialize and connect
        time.sleep(10)
        
        # 1. Connectivity Test
        info('*** Phase 1: Verification (Pingall)\n')
        net.pingAll()
        time.sleep(5)

        # 2. Continuous Traffic
        info('*** Phase 2: Generating Continuous Background Traffic (30s)\n')
        h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')
        
        # Start background pings
        h1.cmd('ping -i 0.5 %s > /dev/null &' % h2.IP())
        h2.cmd('ping -i 0.5 %s > /dev/null &' % h3.IP())
        h3.cmd('ping -i 0.5 %s > /dev/null &' % h4.IP())
        
        time.sleep(30)
        
        # 3. Attack Simulation
        info('*** Phase 3: Launching Host Location Hijack Attack (30s)\n')
        
        # Ensure attack script path (assuming mapped volume at /workspace)
        # We will look for it in the root or 'attacker' subdir
        attack_script = "attacker/host_location_hijack.py"
        if not os.path.exists(attack_script):
             if os.path.exists("host_location_hijack.py"):
                 attack_script = "host_location_hijack.py"
             else:
                 info('!!! Attack script not found. Skipping attack phase.\n')
                 attack_script = None

        if attack_script:
            # Target: h2 (10.0.0.2), Attacker: h1 (spoofing h2's IP)
            target_ip = h2.IP()
            fake_mac = "00:00:00:00:00:99"
            
            info('*** Attacker h1 starting hijack against %s using %s...\n' % (target_ip, attack_script))
            h1.cmd('python3 %s %s %s &' % (attack_script, target_ip, fake_mac))
        
        time.sleep(30)
        
        info('*** Stopping Background Traffic\n')
        h1.cmd('killall ping')
        h2.cmd('killall ping')
        h3.cmd('killall ping')
        
        info('*** Phase 4: Post-Attack Verification\n')
        net.pingAll()

    except Exception as e:
        info('!!! Exception: %s\n' % e)
    finally:
        info('*** Stopping Network\n')
        net.stop()

if __name__ == '__main__':
    run_scenario()
