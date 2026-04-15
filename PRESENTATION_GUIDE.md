# What You Have to Present

## 1. Title
**SDN-Based Firewall using Mininet and Ryu**

## 2. Problem Statement
Traditional firewalls are static and difficult to manage at network scale. This project uses Software Defined Networking to centrally control traffic filtering. The controller decides whether traffic should be allowed or blocked and installs OpenFlow rules in the switch accordingly.

## 3. Objective
To develop a controller-based firewall that blocks or allows communication between hosts using rule-based OpenFlow flow entries.

## 4. Tools Used
- Mininet
- Open vSwitch
- Ryu Controller
- Python
- Flask Dashboard
- iperf
- Optional Wireshark

## 5. Topology Explanation
I used a star topology with one switch and four hosts. This is simple, clear, and ideal for demonstrating host-to-host and port-based access control.

## 6. Firewall Logic
The controller installs high-priority deny rules for blocked traffic patterns. For allowed traffic, it behaves like a learning switch and installs forwarding rules dynamically after packet_in events.

## 7. Rules Implemented
- h1 cannot talk to h3 at all
- h2 cannot access h4 on TCP port 80
- h4 cannot send UDP traffic to h1 on port 53
- h1 can ping h2 successfully

## 8. Functional Demo Flow
First, I start the Ryu controller. Then I start the Mininet topology and connect the switch to the controller. After that, I run live tests to prove that allowed traffic succeeds and blocked traffic fails.

## 9. Demo Tests to Show
### Allowed case
`h1 ping -c 3 h2`

### Blocked case
`h1 ping -c 3 h3`

### Port-block case
Run HTTP server on h4, then try curl from h2.

### Performance case
Run iperf between h1 and h2.

## 10. Analysis to Say
- Ping shows connectivity or packet loss.
- iperf shows throughput for allowed traffic.
- Flow table proves OpenFlow rule installation.
- Dashboard shows blocked packet logs and flow statistics.

## 11. Why this project is good
This project is not just a simple learning switch. It adds firewall logic, protocol/port filtering, monitoring, logging, and a UI dashboard for presentation.

## 12. Final Conclusion
The project proves that SDN allows centralized, programmable, and flexible firewall enforcement using OpenFlow.
