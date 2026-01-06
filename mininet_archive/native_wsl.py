from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def run_topology():
    setLogLevel('info')

    # IMPORTANT: Use UserSwitch for WSL2 compatibility without custom kernel
    # Connect to controller on Windows Host (access via default gateway usually, or localhost if mirrored)
    # In WSL2, localhost often maps to Windows localhost, but let's be robust.
    
    net = Mininet(topo=None,
                  build=False,
                  ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    # Port 6653 is what our Floodlight on Windows uses
    c0 = net.addController(name='c0',
                           controller=RemoteController,
                           ip='127.0.0.1', 
                           port=6653)

    info( '*** Adding switches\n' )
    # datapath='user' is the KEY for WSL2 stability
    s1 = net.addSwitch('s1', cls=UserSwitch)

    info( '*** Adding hosts\n' )
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    h3 = net.addHost('h3', ip='10.0.0.3')
    h4 = net.addHost('h4', ip='10.0.0.4')

    info( '*** Creating links\n' )
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    info( '*** Starting network\n' )
    net.build()
    c0.start()
    s1.start([c0])

    info( '*** Running CLI\n' )
    CLI(net)

    info( '*** Stopping network\n' )
    net.stop()

if __name__ == '__main__':
    run_topology()
