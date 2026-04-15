from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp
from ryu.lib import hub
from datetime import datetime
import os
import json


class SDNFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.flow_stats_cache = []
        self.monitor_thread = hub.spawn(self._monitor)

        self.log_file = "logs/blocked_packets.log"
        self.stats_file = "logs/flow_stats.json"
        self.rules_file = "logs/rules.json"
        self.events_file = "logs/events.log"

        self.policies = [
            {
                "id": 1,
                "name": "Block all traffic from h1 to h3",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.3",
                "ip_proto": None,
                "dst_port": None,
                "action": "deny",
                "priority": 310,
                "description": "Complete host-to-host isolation demo",
            },
            {
                "id": 2,
                "name": "Block HTTP from h2 to h4",
                "src_ip": "10.0.0.2",
                "dst_ip": "10.0.0.4",
                "ip_proto": 6,
                "dst_port": 80,
                "action": "deny",
                "priority": 320,
                "description": "Blocks TCP/80 web access",
            },
            {
                "id": 3,
                "name": "Block DNS-style UDP from h4 to h1",
                "src_ip": "10.0.0.4",
                "dst_ip": "10.0.0.1",
                "ip_proto": 17,
                "dst_port": 53,
                "action": "deny",
                "priority": 320,
                "description": "Blocks UDP/53 traffic",
            },
            {
                "id": 4,
                "name": "Allow ICMP from h1 to h2",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "ip_proto": 1,
                "dst_port": None,
                "action": "allow",
                "priority": 330,
                "description": "Positive connectivity case for demo",
            },
        ]

        self._ensure_files()
        self._dump_rules()
        self._log_event("Controller initialized")

    def _ensure_files(self):
        os.makedirs("logs", exist_ok=True)
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w", encoding="utf-8") as f:
                f.write("timestamp,src_ip,dst_ip,proto,src_port,dst_port,rule\n")
        if not os.path.exists(self.events_file):
            with open(self.events_file, "w", encoding="utf-8") as f:
                f.write("timestamp,event\n")
        if not os.path.exists(self.stats_file):
            with open(self.stats_file, "w", encoding="utf-8") as f:
                json.dump([], f)

    def _dump_rules(self):
        with open(self.rules_file, "w", encoding="utf-8") as f:
            json.dump(self.policies, f, indent=2)

    def _log_event(self, event):
        ts = datetime.now().isoformat()
        with open(self.events_file, "a", encoding="utf-8") as f:
            f.write(f"{ts},{event}\n")
        self.logger.info(event)

    def _write_block_log(self, src_ip, dst_ip, proto, src_port, dst_port, rule_name):
        line = f"{datetime.now().isoformat()},{src_ip},{dst_ip},{proto},{src_port},{dst_port},{rule_name}\n"
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(line)
        self._log_event(
            f"BLOCKED packet {src_ip}->{dst_ip} proto={proto} sport={src_port} dport={dst_port} rule={rule_name}"
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        match_arp = parser.OFPMatch(eth_type=0x0806)
        actions_arp = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 200, match_arp, actions_arp)

        self.install_firewall_rules(datapath)
        self._log_event(f"Switch s{datapath.id} connected and base rules installed")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=instructions,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=instructions,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
            )
        datapath.send_msg(mod)

    def add_drop_flow(self, datapath, priority, match, idle_timeout=0, hard_timeout=0):
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=[],
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    def install_firewall_rules(self, datapath):
        parser = datapath.ofproto_parser
        for rule in self.policies:
            if rule["action"] != "deny":
                continue

            kwargs = {
                "eth_type": 0x0800,
                "ipv4_src": rule["src_ip"],
                "ipv4_dst": rule["dst_ip"],
            }
            if rule["ip_proto"] is not None:
                kwargs["ip_proto"] = rule["ip_proto"]
                if rule["ip_proto"] == 6 and rule["dst_port"] is not None:
                    kwargs["tcp_dst"] = rule["dst_port"]
                elif rule["ip_proto"] == 17 and rule["dst_port"] is not None:
                    kwargs["udp_dst"] = rule["dst_port"]

            match = parser.OFPMatch(**kwargs)
            self.add_drop_flow(datapath, rule["priority"], match)
            self._log_event(f"Installed DENY rule: {rule['name']}")

    def is_blocked(self, src_ip, dst_ip, proto=None, dst_port=None):
        for rule in self.policies:
            if rule["action"] != "deny":
                continue
            if src_ip != rule["src_ip"] or dst_ip != rule["dst_ip"]:
                continue
            if rule["ip_proto"] is not None and proto != rule["ip_proto"]:
                continue
            if rule["dst_port"] is not None and dst_port != rule["dst_port"]:
                continue
            return True, rule["name"]
        return False, None

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return

        dst = eth_pkt.dst
        src = eth_pkt.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        if ipv4_pkt:
            proto = ipv4_pkt.proto
            src_port = tcp_pkt.src_port if tcp_pkt else (udp_pkt.src_port if udp_pkt else None)
            dst_port = tcp_pkt.dst_port if tcp_pkt else (udp_pkt.dst_port if udp_pkt else None)
            blocked, rule_name = self.is_blocked(ipv4_pkt.src, ipv4_pkt.dst, proto, dst_port)
            if blocked:
                self._write_block_log(ipv4_pkt.src, ipv4_pkt.dst, proto, src_port, dst_port, rule_name)
                return

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD and ipv4_pkt:
            match_kwargs = {
                "in_port": in_port,
                "eth_type": 0x0800,
                "ipv4_src": ipv4_pkt.src,
                "ipv4_dst": ipv4_pkt.dst,
            }
            if tcp_pkt:
                match_kwargs["ip_proto"] = 6
            elif udp_pkt:
                match_kwargs["ip_proto"] = 17
            elif icmp_pkt:
                match_kwargs["ip_proto"] = 1

            match = parser.OFPMatch(**match_kwargs)
            self.add_flow(datapath, 100, match, actions, idle_timeout=60, hard_timeout=180)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        snapshot = []
        for stat in sorted([flow for flow in body if flow.priority > 0], key=lambda f: (f.priority, str(f.match))):
            snapshot.append({
                "priority": stat.priority,
                "packet_count": stat.packet_count,
                "byte_count": stat.byte_count,
                "match": str(stat.match),
            })
            self.logger.info(
                "priority=%s packets=%s bytes=%s match=%s",
                stat.priority, stat.packet_count, stat.byte_count, stat.match,
            )
        self.flow_stats_cache = snapshot
        with open(self.stats_file, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)
