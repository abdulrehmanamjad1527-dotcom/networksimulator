#!/usr/bin/env python3
"""
Network Traffic Analyzer
=========================
Captures live network traffic and displays it in a real-time
web dashboard with threat detection, protocol breakdown,
top talkers, and packet inspector.

Install dependencies:
    pip install scapy flask

Run:
    python network_analyzer.py

Then open: http://localhost:5000

⚠️  Run as Administrator/sudo for packet capture to work.
"""

import json
import time
import threading
import socket
import struct
import os
import sys
from datetime import datetime
from collections import defaultdict, deque
from flask import Flask, render_template_string, jsonify

# ── Check for scapy ──────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not installed. Running in DEMO mode.")
    print("    Install with: pip install scapy")

app = Flask(__name__)

# ── Global State ──────────────────────────────
class TrafficState:
    def __init__(self):
        self.packets          = deque(maxlen=200)   # last 200 packets
        self.total_packets    = 0
        self.total_bytes      = 0
        self.protocol_counts  = defaultdict(int)
        self.ip_counts        = defaultdict(int)    # top talkers
        self.port_counts      = defaultdict(int)    # top ports
        self.alerts           = deque(maxlen=50)    # threat alerts
        self.packets_per_sec  = deque(maxlen=60)    # last 60 seconds
        self.bytes_per_sec    = deque(maxlen=60)
        self.start_time       = datetime.now()
        self.lock             = threading.Lock()
        self._sec_packets     = 0
        self._sec_bytes       = 0

state = TrafficState()

# ── Threat Detection Rules ────────────────────
SUSPICIOUS_PORTS = {
    23:   ("Telnet",        "CRITICAL", "Unencrypted remote access detected"),
    1433: ("MSSQL",         "HIGH",     "Database port exposed"),
    3389: ("RDP",           "HIGH",     "Remote desktop detected"),
    4444: ("Metasploit",    "CRITICAL", "Known Metasploit default port"),
    6666: ("IRC/Botnet",    "CRITICAL", "Known botnet communication port"),
    6667: ("IRC/Botnet",    "CRITICAL", "Known botnet communication port"),
    31337:("Elite Hacker",  "CRITICAL", "Known hacking tool port"),
    1234: ("Backdoor",      "HIGH",     "Common backdoor port"),
    5555: ("Android ADB",   "MEDIUM",   "Android debug bridge detected"),
    8080: ("HTTP Proxy",    "LOW",      "Alternate HTTP port in use"),
}

BROADCAST_THRESHOLD = 50   # packets/sec from one IP = potential flood
DNS_THRESHOLD       = 20   # DNS requests/sec = potential exfiltration
SYN_THRESHOLD       = 30   # SYN packets/sec = potential SYN flood

ip_syn_counts    = defaultdict(int)
ip_packet_counts = defaultdict(int)
dns_query_counts = defaultdict(int)

def check_threats(pkt_info):
    """Run threat detection on a parsed packet."""
    alerts = []
    src   = pkt_info.get('src_ip', '')
    dport = pkt_info.get('dst_port', 0)
    proto = pkt_info.get('protocol', '')
    flags = pkt_info.get('flags', '')

    # Suspicious port check
    if dport in SUSPICIOUS_PORTS:
        name, severity, desc = SUSPICIOUS_PORTS[dport]
        alerts.append({
            "time":     pkt_info['time'],
            "severity": severity,
            "type":     f"Suspicious Port — {name}",
            "detail":   f"{src} → port {dport} | {desc}",
            "src":      src
        })

    # SYN flood detection
    if proto == "TCP" and "S" in flags and "A" not in flags:
        ip_syn_counts[src] += 1
        if ip_syn_counts[src] == SYN_THRESHOLD:
            alerts.append({
                "time":     pkt_info['time'],
                "severity": "CRITICAL",
                "type":     "Possible SYN Flood",
                "detail":   f"{src} sent {SYN_THRESHOLD}+ SYN packets — potential DoS attack",
                "src":      src
            })

    # DNS exfiltration check
    if dport == 53:
        dns_query_counts[src] += 1
        if dns_query_counts[src] == DNS_THRESHOLD:
            alerts.append({
                "time":     pkt_info['time'],
                "severity": "HIGH",
                "type":     "Possible DNS Exfiltration",
                "detail":   f"{src} made {DNS_THRESHOLD}+ DNS queries — possible data exfiltration",
                "src":      src
            })

    # ARP spoofing detection
    if proto == "ARP" and pkt_info.get('arp_op') == "who-has":
        ip_packet_counts[src] += 1
        if ip_packet_counts[src] == BROADCAST_THRESHOLD:
            alerts.append({
                "time":     pkt_info['time'],
                "severity": "HIGH",
                "type":     "Possible ARP Scan",
                "detail":   f"{src} sent {BROADCAST_THRESHOLD}+ ARP requests — network scanning?",
                "src":      src
            })

    return alerts

# ── Packet Parser ─────────────────────────────
def parse_packet(pkt):
    """Parse a scapy packet into a dict."""
    info = {
        "time":     datetime.now().strftime("%H:%M:%S"),
        "size":     len(pkt),
        "protocol": "OTHER",
        "src_ip":   "",
        "dst_ip":   "",
        "src_port": 0,
        "dst_port": 0,
        "flags":    "",
        "info":     "",
        "arp_op":   ""
    }

    if pkt.haslayer(ARP):
        info["protocol"] = "ARP"
        info["src_ip"]   = pkt[ARP].psrc
        info["dst_ip"]   = pkt[ARP].pdst
        info["arp_op"]   = "who-has" if pkt[ARP].op == 1 else "is-at"
        info["info"]     = f"ARP {info['arp_op']} {info['dst_ip']}"

    elif pkt.haslayer(IP):
        info["src_ip"] = pkt[IP].src
        info["dst_ip"] = pkt[IP].dst

        if pkt.haslayer(TCP):
            info["protocol"] = "TCP"
            info["src_port"] = pkt[TCP].sport
            info["dst_port"] = pkt[TCP].dport
            flags = pkt[TCP].flags
            flag_str = ""
            if flags & 0x02: flag_str += "S"
            if flags & 0x10: flag_str += "A"
            if flags & 0x01: flag_str += "F"
            if flags & 0x04: flag_str += "R"
            if flags & 0x08: flag_str += "P"
            info["flags"] = flag_str
            info["info"]  = f"TCP {pkt[TCP].sport} → {pkt[TCP].dport} [{flag_str}]"

            # Identify common services
            if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                info["protocol"] = "HTTP"
            elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                info["protocol"] = "HTTPS"
            elif pkt[TCP].dport == 22 or pkt[TCP].sport == 22:
                info["protocol"] = "SSH"

        elif pkt.haslayer(UDP):
            info["protocol"] = "UDP"
            info["src_port"] = pkt[UDP].sport
            info["dst_port"] = pkt[UDP].dport
            info["info"]     = f"UDP {pkt[UDP].sport} → {pkt[UDP].dport}"

            if pkt.haslayer(DNS):
                info["protocol"] = "DNS"
                try:
                    info["info"] = f"DNS Query: {pkt[DNS].qd.qname.decode()}"
                except:
                    info["info"] = "DNS Packet"

        elif pkt.haslayer(ICMP):
            info["protocol"] = "ICMP"
            icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
            info["info"] = icmp_types.get(pkt[ICMP].type, f"ICMP Type {pkt[ICMP].type}")

    return info

def process_packet(pkt):
    """Called for each captured packet."""
    global state
    info = parse_packet(pkt)

    with state.lock:
        state.total_packets += 1
        state.total_bytes   += info['size']
        state._sec_packets  += 1
        state._sec_bytes    += info['size']
        state.protocol_counts[info['protocol']] += 1

        if info['src_ip']:
            state.ip_counts[info['src_ip']] += 1
        if info['dst_port']:
            state.port_counts[info['dst_port']] += 1

        state.packets.appendleft(info)

        # Threat detection
        alerts = check_threats(info)
        for alert in alerts:
            state.alerts.appendleft(alert)

# ── Demo Mode (no scapy) ──────────────────────
import random

DEMO_IPS    = ["192.168.1.1","192.168.1.105","10.0.0.5","8.8.8.8","172.16.0.1","192.168.1.200","185.234.218.50"]
DEMO_PROTOS = ["TCP","UDP","HTTP","HTTPS","DNS","ICMP","ARP","SSH"]
DEMO_PORTS  = [80,443,53,22,8080,3389,4444,23,1433,8443]

def generate_demo_packet():
    """Generate a fake packet for demo mode."""
    proto = random.choice(DEMO_PROTOS)
    src   = random.choice(DEMO_IPS)
    dst   = random.choice(DEMO_IPS)
    sport = random.randint(1024, 65535)
    dport = random.choice(DEMO_PORTS)
    size  = random.randint(64, 1500)

    info = {
        "time":     datetime.now().strftime("%H:%M:%S"),
        "size":     size,
        "protocol": proto,
        "src_ip":   src,
        "dst_ip":   dst,
        "src_port": sport,
        "dst_port": dport,
        "flags":    random.choice(["S","SA","A","PA","F",""]),
        "info":     f"{proto} {src}:{sport} → {dst}:{dport}",
        "arp_op":   ""
    }

    with state.lock:
        state.total_packets += 1
        state.total_bytes   += size
        state._sec_packets  += 1
        state._sec_bytes    += size
        state.protocol_counts[proto] += 1
        state.ip_counts[src]         += 1
        state.port_counts[dport]     += 1
        state.packets.appendleft(info)

        alerts = check_threats(info)
        for alert in alerts:
            state.alerts.appendleft(alert)

def demo_thread():
    """Generate demo traffic continuously."""
    while True:
        for _ in range(random.randint(1, 5)):
            generate_demo_packet()
        time.sleep(0.3)

# ── Stats ticker (packets/sec) ────────────────
def stats_ticker():
    """Record packets/sec every second."""
    while True:
        time.sleep(1)
        with state.lock:
            state.packets_per_sec.append(state._sec_packets)
            state.bytes_per_sec.append(state._sec_bytes)
            state._sec_packets = 0
            state._sec_bytes   = 0
            # Reset per-second threat counters
            ip_syn_counts.clear()
            dns_query_counts.clear()
            ip_packet_counts.clear()

# ── API Endpoints ─────────────────────────────
@app.route('/api/stats')
def api_stats():
    with state.lock:
        uptime = int((datetime.now() - state.start_time).total_seconds())

        # Top 5 IPs
        top_ips = sorted(state.ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        # Top 5 ports
        top_ports = sorted(state.port_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        return jsonify({
            "total_packets":    state.total_packets,
            "total_bytes":      state.total_bytes,
            "uptime":           uptime,
            "alerts_count":     len(state.alerts),
            "protocol_counts":  dict(state.protocol_counts),
            "top_ips":          top_ips,
            "top_ports":        [[str(p), c] for p, c in top_ports],
            "packets_per_sec":  list(state.packets_per_sec),
            "bytes_per_sec":    list(state.bytes_per_sec),
            "packets":          list(state.packets)[:50],
            "alerts":           list(state.alerts)[:20],
            "demo_mode":        not SCAPY_AVAILABLE
        })

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML)

# ── Dashboard HTML ────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetWatch — Network Traffic Analyzer</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap');

  :root {
    --bg:        #060910;
    --surface:   #0d1117;
    --surface2:  #161b22;
    --border:    #21262d;
    --green:     #00ff88;
    --blue:      #4facfe;
    --red:       #ff4757;
    --orange:    #ffa502;
    --yellow:    #ffdd59;
    --purple:    #a29bfe;
    --text:      #e6edf3;
    --muted:     #6e7681;
    --mono:      'JetBrains Mono', monospace;
    --sans:      'Inter', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--sans);
         min-height: 100vh; overflow-x: hidden; }

  /* ── Scanline overlay ── */
  body::before { content: ''; position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px,
    rgba(0,255,136,0.015) 2px, rgba(0,255,136,0.015) 4px); }

  /* ── Header ── */
  .header { display: flex; align-items: center; justify-content: space-between;
            padding: 16px 28px; border-bottom: 1px solid var(--border);
            background: rgba(13,17,23,0.95); position: sticky; top: 0; z-index: 100;
            backdrop-filter: blur(10px); }
  .logo { font-family: var(--mono); font-size: 1.1rem; font-weight: 700; color: var(--green);
          letter-spacing: 2px; display: flex; align-items: center; gap: 10px; }
  .logo-dot { width: 8px; height: 8px; background: var(--green); border-radius: 50%;
              animation: pulse-dot 1s infinite; }
  @keyframes pulse-dot { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.4;transform:scale(0.8)} }
  .status-bar { display: flex; gap: 20px; font-family: var(--mono); font-size: 0.75rem; color: var(--muted); }
  .status-item span { color: var(--green); }
  .demo-badge { background: rgba(255,165,0,0.15); border: 1px solid var(--orange);
                color: var(--orange); padding: 4px 10px; border-radius: 4px;
                font-size: 0.72rem; font-family: var(--mono); display: none; }

  /* ── Layout ── */
  .container { max-width: 1400px; margin: 0 auto; padding: 20px 24px; position: relative; z-index: 1; }

  /* ── Stat Cards ── */
  .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
               padding: 20px; position: relative; overflow: hidden; }
  .stat-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; }
  .stat-card.green::before  { background: var(--green); }
  .stat-card.blue::before   { background: var(--blue); }
  .stat-card.red::before    { background: var(--red); }
  .stat-card.orange::before { background: var(--orange); }
  .stat-label { font-size: 0.72rem; color: var(--muted); text-transform: uppercase;
                letter-spacing: 1.5px; margin-bottom: 8px; }
  .stat-value { font-family: var(--mono); font-size: 1.8rem; font-weight: 700; }
  .stat-card.green  .stat-value { color: var(--green); }
  .stat-card.blue   .stat-value { color: var(--blue); }
  .stat-card.red    .stat-value { color: var(--red); }
  .stat-card.orange .stat-value { color: var(--orange); }
  .stat-sub { font-size: 0.75rem; color: var(--muted); margin-top: 4px; font-family: var(--mono); }

  /* ── Main grid ── */
  .main-grid { display: grid; grid-template-columns: 1fr 1fr 340px; gap: 16px; margin-bottom: 16px; }
  .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  .panel-header { padding: 12px 16px; border-bottom: 1px solid var(--border);
                  display: flex; align-items: center; justify-content: space-between; }
  .panel-title { font-size: 0.78rem; font-weight: 600; text-transform: uppercase;
                 letter-spacing: 1.5px; color: var(--muted); font-family: var(--mono); }
  .panel-badge { font-family: var(--mono); font-size: 0.7rem; padding: 2px 8px;
                 border-radius: 3px; background: var(--surface2); color: var(--green); }

  /* ── Protocol bars ── */
  .proto-list { padding: 16px; }
  .proto-item { margin-bottom: 12px; }
  .proto-row { display: flex; justify-content: space-between; margin-bottom: 5px;
               font-family: var(--mono); font-size: 0.78rem; }
  .proto-name { color: var(--text); }
  .proto-count { color: var(--muted); }
  .proto-bar-bg { height: 4px; background: var(--surface2); border-radius: 2px; }
  .proto-bar { height: 4px; border-radius: 2px; transition: width 0.5s ease; }

  /* ── Top IPs ── */
  .ip-list { padding: 12px 16px; }
  .ip-item { display: flex; align-items: center; gap: 10px; padding: 8px 0;
             border-bottom: 1px solid var(--border); font-family: var(--mono); font-size: 0.78rem; }
  .ip-item:last-child { border-bottom: none; }
  .ip-rank { color: var(--muted); width: 16px; text-align: center; }
  .ip-addr { color: var(--blue); flex: 1; }
  .ip-count { color: var(--green); font-weight: 600; }
  .ip-bar { flex: 2; height: 3px; background: var(--surface2); border-radius: 2px; overflow: hidden; }
  .ip-bar-fill { height: 100%; background: var(--blue); border-radius: 2px; transition: width 0.5s; }

  /* ── Alerts ── */
  .alerts-panel { grid-column: 3; grid-row: 1 / 3; }
  .alert-list { padding: 12px; max-height: 500px; overflow-y: auto; }
  .alert-item { background: var(--surface2); border-radius: 6px; padding: 10px 12px;
                margin-bottom: 8px; border-left: 3px solid; animation: slide-in 0.3s ease; }
  @keyframes slide-in { from{opacity:0;transform:translateY(-8px)} to{opacity:1;transform:translateY(0)} }
  .alert-item.CRITICAL { border-color: var(--red); }
  .alert-item.HIGH     { border-color: var(--orange); }
  .alert-item.MEDIUM   { border-color: var(--yellow); }
  .alert-item.LOW      { border-color: var(--blue); }
  .alert-sev  { font-family: var(--mono); font-size: 0.65rem; font-weight: 700;
                text-transform: uppercase; letter-spacing: 1px; margin-bottom: 3px; }
  .CRITICAL .alert-sev { color: var(--red); }
  .HIGH .alert-sev     { color: var(--orange); }
  .MEDIUM .alert-sev   { color: var(--yellow); }
  .LOW .alert-sev      { color: var(--blue); }
  .alert-type   { font-size: 0.82rem; font-weight: 600; margin-bottom: 3px; }
  .alert-detail { font-size: 0.74rem; color: var(--muted); font-family: var(--mono); }
  .alert-time   { font-size: 0.68rem; color: var(--muted); margin-top: 4px; font-family: var(--mono); }
  .no-alerts { text-align: center; padding: 40px 20px; color: var(--muted);
               font-family: var(--mono); font-size: 0.8rem; }

  /* ── Sparkline ── */
  .sparkline-wrap { padding: 16px; }
  canvas { width: 100% !important; display: block; }

  /* ── Packet table ── */
  .packet-section { margin-bottom: 16px; }
  .packet-table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 0.75rem; }
  .packet-table th { padding: 8px 12px; text-align: left; color: var(--muted);
                     text-transform: uppercase; letter-spacing: 1px; font-size: 0.65rem;
                     border-bottom: 1px solid var(--border); font-weight: 600; }
  .packet-table td { padding: 7px 12px; border-bottom: 1px solid rgba(33,38,45,0.5); }
  .packet-table tr:hover td { background: var(--surface2); }
  .proto-tag { display: inline-block; padding: 2px 7px; border-radius: 3px;
               font-size: 0.68rem; font-weight: 700; }
  .p-TCP   { background: rgba(79,172,254,0.15); color: #4facfe; }
  .p-UDP   { background: rgba(162,155,254,0.15); color: #a29bfe; }
  .p-HTTP  { background: rgba(0,255,136,0.15); color: #00ff88; }
  .p-HTTPS { background: rgba(0,255,136,0.2); color: #00ff88; }
  .p-DNS   { background: rgba(255,221,89,0.15); color: #ffdd59; }
  .p-ICMP  { background: rgba(255,165,0,0.15); color: #ffa502; }
  .p-ARP   { background: rgba(255,71,87,0.15); color: #ff4757; }
  .p-SSH   { background: rgba(162,155,254,0.2); color: #a29bfe; }
  .p-OTHER { background: rgba(110,118,129,0.15); color: #6e7681; }
  .src-ip { color: var(--blue); }
  .dst-ip { color: var(--purple); }
  .pkt-size { color: var(--muted); }
  .table-wrap { max-height: 320px; overflow-y: auto; }

  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: var(--surface); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  @media(max-width:1100px) {
    .main-grid { grid-template-columns: 1fr 1fr; }
    .alerts-panel { grid-column: 1 / 3; grid-row: auto; }
    .stat-grid { grid-template-columns: repeat(2,1fr); }
  }
  @media(max-width:640px) {
    .stat-grid { grid-template-columns: 1fr 1fr; }
    .main-grid { grid-template-columns: 1fr; }
    .alerts-panel { grid-column: 1; }
  }
</style>
</head>
<body>

<div class="header">
  <div class="logo">
    <div class="logo-dot"></div>
    NETWATCH
  </div>
  <div class="status-bar">
    <div class="status-item">UPTIME <span id="uptime">00:00</span></div>
    <div class="status-item">PKT/S <span id="pps">0</span></div>
    <div class="status-item">BW <span id="bps">0 B/s</span></div>
  </div>
  <div class="demo-badge" id="demo-badge">⚠ DEMO MODE</div>
</div>

<div class="container">

  <!-- Stat Cards -->
  <div class="stat-grid">
    <div class="stat-card green">
      <div class="stat-label">Total Packets</div>
      <div class="stat-value" id="total-packets">0</div>
      <div class="stat-sub" id="pps-sub">0 pkt/s</div>
    </div>
    <div class="stat-card blue">
      <div class="stat-label">Data Captured</div>
      <div class="stat-value" id="total-bytes">0 B</div>
      <div class="stat-sub" id="bps-sub">0 B/s</div>
    </div>
    <div class="stat-card red">
      <div class="stat-label">Threats Detected</div>
      <div class="stat-value" id="alerts-count">0</div>
      <div class="stat-sub">security alerts</div>
    </div>
    <div class="stat-card orange">
      <div class="stat-label">Unique IPs</div>
      <div class="stat-value" id="unique-ips">0</div>
      <div class="stat-sub">hosts seen</div>
    </div>
  </div>

  <!-- Main grid -->
  <div class="main-grid">

    <!-- Protocol Breakdown -->
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Protocol Breakdown</span>
        <span class="panel-badge" id="proto-total">0 types</span>
      </div>
      <div class="proto-list" id="proto-list"></div>
    </div>

    <!-- Top Talkers -->
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">Top Talkers</span>
        <span class="panel-badge">By Packet Count</span>
      </div>
      <div class="ip-list" id="ip-list"></div>
    </div>

    <!-- Alerts -->
    <div class="panel alerts-panel">
      <div class="panel-header">
        <span class="panel-title">🚨 Threat Alerts</span>
        <span class="panel-badge" id="alert-badge">0 alerts</span>
      </div>
      <div class="alert-list" id="alert-list">
        <div class="no-alerts">No threats detected yet.<br>Monitoring traffic...</div>
      </div>
    </div>

    <!-- Sparkline -->
    <div class="panel" style="grid-column:1/3">
      <div class="panel-header">
        <span class="panel-title">Packets / Second</span>
        <span class="panel-badge">Last 60s</span>
      </div>
      <div class="sparkline-wrap">
        <canvas id="sparkline" height="80"></canvas>
      </div>
    </div>

  </div>

  <!-- Packet Table -->
  <div class="panel packet-section">
    <div class="panel-header">
      <span class="panel-title">Live Packet Feed</span>
      <span class="panel-badge" id="pkt-count">0 packets</span>
    </div>
    <div class="table-wrap">
      <table class="packet-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Protocol</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Size</th>
            <th>Info</th>
          </tr>
        </thead>
        <tbody id="packet-tbody"></tbody>
      </table>
    </div>
  </div>

</div>

<script>
const PROTO_COLORS = {
  TCP:'#4facfe',UDP:'#a29bfe',HTTP:'#00ff88',HTTPS:'#00c96e',
  DNS:'#ffdd59',ICMP:'#ffa502',ARP:'#ff4757',SSH:'#d6a0ff',OTHER:'#6e7681'
};

function fmtBytes(b) {
  if(b < 1024) return b + ' B';
  if(b < 1048576) return (b/1024).toFixed(1) + ' KB';
  return (b/1048576).toFixed(1) + ' MB';
}

function fmtUptime(s) {
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
  if(h > 0) return `${h}h ${m}m`;
  return `${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
}

// ── Sparkline canvas ──
const canvas = document.getElementById('sparkline');
const ctx    = canvas.getContext('2d');

function drawSparkline(data) {
  const W = canvas.offsetWidth, H = 80;
  canvas.width = W; canvas.height = H;
  ctx.clearRect(0,0,W,H);
  if(!data.length) return;

  const max = Math.max(...data, 1);
  const pts = data.map((v,i) => ({
    x: (i / (data.length-1)) * W,
    y: H - (v/max) * (H-10) - 5
  }));

  // Gradient fill
  const grad = ctx.createLinearGradient(0,0,0,H);
  grad.addColorStop(0, 'rgba(0,255,136,0.3)');
  grad.addColorStop(1, 'rgba(0,255,136,0)');
  ctx.beginPath();
  ctx.moveTo(pts[0].x, H);
  pts.forEach(p => ctx.lineTo(p.x, p.y));
  ctx.lineTo(pts[pts.length-1].x, H);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Line
  ctx.beginPath();
  pts.forEach((p,i) => i===0 ? ctx.moveTo(p.x,p.y) : ctx.lineTo(p.x,p.y));
  ctx.strokeStyle = '#00ff88';
  ctx.lineWidth = 2;
  ctx.stroke();
}

// ── Update dashboard ──
function update() {
  fetch('/api/stats')
    .then(r => r.json())
    .then(data => {
      // Demo badge
      if(data.demo_mode) document.getElementById('demo-badge').style.display='block';

      // Stats
      const pps = data.packets_per_sec.length ? data.packets_per_sec[data.packets_per_sec.length-1] : 0;
      const bps = data.bytes_per_sec.length   ? data.bytes_per_sec[data.bytes_per_sec.length-1]     : 0;
      document.getElementById('total-packets').textContent = data.total_packets.toLocaleString();
      document.getElementById('total-bytes').textContent   = fmtBytes(data.total_bytes);
      document.getElementById('alerts-count').textContent  = data.alerts_count;
      document.getElementById('unique-ips').textContent    = data.top_ips.length;
      document.getElementById('uptime').textContent        = fmtUptime(data.uptime);
      document.getElementById('pps').textContent           = pps;
      document.getElementById('bps').textContent           = fmtBytes(bps) + '/s';
      document.getElementById('pps-sub').textContent       = pps + ' pkt/s';
      document.getElementById('bps-sub').textContent       = fmtBytes(bps) + '/s';
      document.getElementById('pkt-count').textContent     = data.total_packets.toLocaleString() + ' packets';

      // Protocols
      const protos = Object.entries(data.protocol_counts).sort((a,b)=>b[1]-a[1]);
      const maxP   = protos.length ? protos[0][1] : 1;
      document.getElementById('proto-total').textContent = protos.length + ' types';
      document.getElementById('proto-list').innerHTML = protos.slice(0,8).map(([name,count]) => `
        <div class="proto-item">
          <div class="proto-row">
            <span class="proto-name">${name}</span>
            <span class="proto-count">${count.toLocaleString()}</span>
          </div>
          <div class="proto-bar-bg">
            <div class="proto-bar" style="width:${(count/maxP*100).toFixed(1)}%;background:${PROTO_COLORS[name]||'#6e7681'}"></div>
          </div>
        </div>`).join('');

      // Top IPs
      const maxIP = data.top_ips.length ? data.top_ips[0][1] : 1;
      document.getElementById('ip-list').innerHTML = data.top_ips.map(([ip,count],i) => `
        <div class="ip-item">
          <span class="ip-rank">${i+1}</span>
          <span class="ip-addr">${ip}</span>
          <div class="ip-bar"><div class="ip-bar-fill" style="width:${(count/maxIP*100).toFixed(1)}%"></div></div>
          <span class="ip-count">${count}</span>
        </div>`).join('');

      // Alerts
      document.getElementById('alert-badge').textContent = data.alerts_count + ' alerts';
      if(data.alerts.length) {
        document.getElementById('alert-list').innerHTML = data.alerts.map(a => `
          <div class="alert-item ${a.severity}">
            <div class="alert-sev">${a.severity}</div>
            <div class="alert-type">${a.type}</div>
            <div class="alert-detail">${a.detail}</div>
            <div class="alert-time">${a.time}</div>
          </div>`).join('');
      }

      // Packets
      document.getElementById('packet-tbody').innerHTML = data.packets.map(p => `
        <tr>
          <td>${p.time}</td>
          <td><span class="proto-tag p-${p.protocol}">${p.protocol}</span></td>
          <td class="src-ip">${p.src_ip || '—'}</td>
          <td class="dst-ip">${p.dst_ip || '—'}</td>
          <td class="pkt-size">${p.size}B</td>
          <td style="color:#6e7681;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${p.info}</td>
        </tr>`).join('');

      // Sparkline
      drawSparkline(data.packets_per_sec);
    })
    .catch(err => console.error('Update error:', err));
}

// Refresh every second
update();
setInterval(update, 1000);
window.addEventListener('resize', () => {
  fetch('/api/stats').then(r=>r.json()).then(d=>drawSparkline(d.packets_per_sec));
});
</script>
</body>
</html>"""

# ── Start capture thread ──────────────────────
def start_capture():
    if SCAPY_AVAILABLE:
        print("[*] Starting packet capture (requires admin/sudo)...")
        try:
            sniff(prn=process_packet, store=False)
        except Exception as e:
            print(f"[!] Capture failed: {e}")
            print("[*] Switching to demo mode...")
            threading.Thread(target=demo_thread, daemon=True).start()
    else:
        threading.Thread(target=demo_thread, daemon=True).start()

# ── Main ──────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "="*50)
    print("  🛡  NETWATCH — Network Traffic Analyzer")
    print("="*50)

    if not SCAPY_AVAILABLE:
        print("  ⚠  Running in DEMO MODE (install scapy for live capture)")
    else:
        print("  ✅  Scapy detected — live capture enabled")

    print(f"\n  📊  Dashboard → http://localhost:5000")
    print("  Press Ctrl+C to stop\n")

    # Start stats ticker
    threading.Thread(target=stats_ticker, daemon=True).start()

    # Start capture
    threading.Thread(target=start_capture, daemon=True).start()

    # Start Flask
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)