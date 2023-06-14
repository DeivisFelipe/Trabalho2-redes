from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink

class BasicTopo(Topo):
    "A LinuxRouter connecting two hosts"

    def build(self, **_opts):
      h1 = self.addHost('h1', ip='10.1.1.1/24', defaultRoute='via 10.1.1.254')
      h2 = self.addHost('h2', ip='10.1.1.2/24', defaultRoute='via 10.1.1.254') 

      self.addLink(h1, h2, cls=TCLink, bw=1, delay='50ms', loss=3) 

def run():
    "Basic example"
    net = Mininet(topo=BasicTopo(), controller=None)
    for _, v in net.nameToNode.items():
     for itf in v.intfList():
      v.cmd('ethtool -K '+itf.name+' tx off rx off') 
    h1 = net.get('h1')
    h1.cmd('iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP') 
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()