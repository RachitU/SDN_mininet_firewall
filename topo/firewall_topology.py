from mininet.topo import Topo


class FirewallTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')

        hosts = [
            ('h1', '10.0.0.1/24', '00:00:00:00:00:01'),
            ('h2', '10.0.0.2/24', '00:00:00:00:00:02'),
            ('h3', '10.0.0.3/24', '00:00:00:00:00:03'),
            ('h4', '10.0.0.4/24', '00:00:00:00:00:04'),
        ]

        for name, ip, mac in hosts:
            host = self.addHost(name, ip=ip, mac=mac)
            self.addLink(host, s1)


topos = {'firewalltopo': FirewallTopo}
