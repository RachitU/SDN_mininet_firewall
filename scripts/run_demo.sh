#!/bin/bash
set -e
sudo mn -c || true
sudo mn --custom topo/firewall_topology.py --topo firewalltopo \
  --controller remote,ip=127.0.0.1,port=6633 \
  --switch ovsk,protocols=OpenFlow13 \
  --mac
