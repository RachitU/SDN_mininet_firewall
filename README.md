# SDN-Based Firewall using Mininet, Ryu, and a Flask Dashboard

## Project Objective
This project implements a controller-based SDN firewall that blocks or allows traffic between hosts using explicit OpenFlow rules. It demonstrates controller-switch interaction, packet_in handling, rule-based filtering, flow monitoring, blocked packet logging, and UI-based visualization.

## Why this project is strong
- Uses **Mininet** and **Ryu**, exactly as required.
- Installs **explicit OpenFlow flow rules**.
- Handles **packet_in events** and installs forwarding rules for allowed traffic.
- Demonstrates **allowed vs blocked** behavior.
- Includes **throughput testing** with `iperf`.
- Includes a polished **web dashboard** for presenting rules, logs, and flow statistics.

## Topology
A star topology is used:
- 1 Open vSwitch: `s1`
- 4 hosts: `h1`, `h2`, `h3`, `h4`

IP assignments:
- `h1` → `10.0.0.1`
- `h2` → `10.0.0.2`
- `h3` → `10.0.0.3`
- `h4` → `10.0.0.4`

## Firewall Rules
1. Block **all traffic** from `h1` to `h3`
2. Block **TCP port 80** from `h2` to `h4`
3. Block **UDP port 53** from `h4` to `h1`
4. Allow **ICMP** from `h1` to `h2`

## Folder Structure
```text
sdn-firewall/
├─ controller/
│  └─ sdn_firewall.py
├─ topo/
│  └─ firewall_topology.py
├─ web/
│  ├─ app.py
│  ├─ templates/
│  │  └─ index.html
│  └─ static/css/
│     └─ style.css
├─ scripts/
│  ├─ run_demo.sh
│  ├─ run_dashboard.sh
│  ├─ show_flows.sh
│  └─ demo_commands.txt
├─ logs/
├─ requirements.txt
└─ README.md
```

## Installation
Use Ubuntu or a Linux VM.

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch python3-pip iperf curl net-tools
pip3 install ryu flask
```

Optional for packet capture:
```bash
sudo apt install -y wireshark
```

## How to Run
### Terminal 1: Start controller
```bash
cd sdn-firewall
ryu-manager controller/sdn_firewall.py
```

### Terminal 2: Start Mininet
```bash
cd sdn-firewall
chmod +x scripts/*.sh
./scripts/run_demo.sh
```

### Terminal 3: Start dashboard UI
```bash
cd sdn-firewall
./scripts/run_dashboard.sh
```

Open:
```text
http://127.0.0.1:5000
```

## Test Cases
### 1) Allowed ping
```bash
mininet> h1 ping -c 3 h2
```
Expected: success

### 2) Blocked ping
```bash
mininet> h1 ping -c 3 h3
```
Expected: 100% packet loss

### 3) Blocked HTTP access
```bash
mininet> h4 python3 -m http.server 80 &
mininet> h2 curl 10.0.0.4
```
Expected: blocked/no response

### 4) Allowed throughput using iperf
```bash
mininet> h2 iperf -s &
mininet> h1 iperf -c 10.0.0.2
```
Expected: successful throughput output

### 5) Flow table inspection
```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```
Expected: deny rules and learned forwarding rules

## Dashboard Features
- Glassmorphism-style UI for a clean presentation
- Shows firewall rules
- Shows recent blocked packets
- Shows flow statistics snapshot
- Shows recent controller events

## What to present
Explain:
1. the problem
2. why SDN is used
3. topology design
4. controller logic
5. firewall rules and what each one blocks
6. two or more live tests
7. flow table changes
8. performance observation using ping and iperf
9. dashboard view for logs and stats

## Viva lines
- SDN separates the control plane from the data plane.
- The controller decides policy centrally and pushes OpenFlow rules to the switch.
- High-priority drop rules enforce firewall behavior.
- Allowed traffic gets forwarding rules installed dynamically.
- Blocked events are logged for monitoring and validation.

## References
- Mininet Documentation
- Ryu SDN Framework Documentation
- OpenFlow 1.3 Specification
