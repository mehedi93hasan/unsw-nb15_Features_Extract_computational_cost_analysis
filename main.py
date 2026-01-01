import customtkinter as ctk
import threading
import pandas as pd
import numpy as np
import os
import time
import re
from collections import defaultdict, deque
from scapy.all import PcapReader, IP, TCP, UDP, Raw

# --- CONFIGURATION ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class UNSW_NB15_FlowTracker:
    """
    "Heavy" Flow Tracker that attempts to extract standard UNSW-NB15 features.
    Even with 100 packets, these features are computationally expensive due to
    state maintenance (ct_ features) and payload inspection.
    """
    
    def __init__(self, timeout=120):
        self.flows = {}
        # GLOBAL STATE TABLES (Required for UNSW 'ct_' features)
        # These track history across ALL flows, making them expensive/memory heavy.
        self.global_src_ip_count = defaultdict(int)
        self.global_dst_ip_count = defaultdict(int)
        self.global_service_count = defaultdict(int)
        
        # Cost Tracking
        self.cost_accumulators = defaultdict(float)
        self.cost_counts = defaultdict(int)

    def get_flow_key(self, pkt):
        """Standard 5-tuple key"""
        if IP not in pkt: return None
        
        src, dst = pkt[IP].src, pkt[IP].dst
        proto = pkt[IP].proto
        sport, dport = 0, 0
        
        if TCP in pkt:
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            
        # Direction-aware key (unlike lightweight, UNSW cares about Source vs Dest)
        # We store both directions in one flow object for simplicity here, 
        # but mark who started it.
        if (src, sport) < (dst, dport):
            return (src, sport, dst, dport, proto)
        else:
            return (dst, dport, src, sport, proto)

    def measure_block(self, name, func):
        """Execute a function and measure its time in nanoseconds."""
        t0 = time.perf_counter_ns()
        result = func()
        t1 = time.perf_counter_ns()
        self.cost_accumulators[name] += (t1 - t0)
        self.cost_counts[name] += 1
        return result

    def process_packet(self, pkt):
        """Process packet and maintain complex state."""
        if IP not in pkt: return

        # 1. GLOBAL STATE UPDATES (Expensive O(1) but frequent)
        # UNSW features like ct_src_ltm need global knowledge of the network
        self.global_src_ip_count[pkt[IP].src] += 1
        self.global_dst_ip_count[pkt[IP].dst] += 1
        
        flow_key = self.get_flow_key(pkt)
        timestamp = float(pkt.time)
        
        if flow_key not in self.flows:
            # Initialize complex flow object
            self.flows[flow_key] = {
                # Basic Info
                'src_ip': pkt[IP].src, 'dst_ip': pkt[IP].dst,
                'sport': 0, 'dport': 0, 'proto': pkt[IP].proto,
                'start_time': timestamp, 'last_time': timestamp,
                
                # Buffers (Limited to 100 as per request)
                'timestamps': deque(maxlen=100),
                'pkt_sizes': deque(maxlen=100),
                'directions': deque(maxlen=100), # 0 for src->dst, 1 for dst->src
                'ttls': deque(maxlen=100),
                'tcp_flags': deque(maxlen=100),
                'seq_nums': deque(maxlen=100),   # Needed for tcprtt
                'ack_nums': deque(maxlen=100),   # Needed for tcprtt
                'payloads': deque(maxlen=100),   # Needed for Content features
                
                # State variables
                'sbytes': 0, 'dbytes': 0,
                'spkts': 0, 'dpkts': 0,
                'swin': 0, 'dwin': 0,
                'syn_time': 0, 'synack_time': 0, 'ack_time': 0 # For RTT
            }
            
            if TCP in pkt:
                self.flows[flow_key]['sport'] = pkt[TCP].sport
                self.flows[flow_key]['dport'] = pkt[TCP].dport
            elif UDP in pkt:
                self.flows[flow_key]['sport'] = pkt[UDP].sport
                self.flows[flow_key]['dport'] = pkt[UDP].dport

        flow = self.flows[flow_key]
        
        # Determine direction
        # We assume the Creator of the flow key is the "Source" (approximated)
        if pkt[IP].src == flow['src_ip']:
            direction = 0 # Source -> Dest
            flow['sbytes'] += len(pkt)
            flow['spkts'] += 1
            if TCP in pkt: flow['swin'] = pkt[TCP].window
        else:
            direction = 1 # Dest -> Source
            flow['dbytes'] += len(pkt)
            flow['dpkts'] += 1
            if TCP in pkt: flow['dwin'] = pkt[TCP].window

        # Append to Buffers
        flow['timestamps'].append(timestamp)
        flow['pkt_sizes'].append(len(pkt))
        flow['directions'].append(direction)
        flow['ttls'].append(pkt[IP].ttl)
        
        if TCP in pkt:
            flow['tcp_flags'].append(pkt[TCP].flags)
            flow['seq_nums'].append(pkt[TCP].seq)
            flow['ack_nums'].append(pkt[TCP].ack)
            
            # Logic for RTT (Round Trip Time) - Stateful & Expensive
            # Capture time of SYN, SYN-ACK, ACK
            flags = pkt[TCP].flags
            if flags & 0x02 and not flags & 0x10: # SYN
                flow['syn_time'] = timestamp
            elif flags & 0x02 and flags & 0x10: # SYN-ACK
                flow['synack_time'] = timestamp
            elif flags & 0x10 and not flags & 0x02: # ACK
                if flow['synack_time'] > 0 and flow['ack_time'] == 0:
                    flow['ack_time'] = timestamp
        else:
            flow['tcp_flags'].append(0)
            flow['seq_nums'].append(0)
            flow['ack_nums'].append(0)

        # Payload extraction (Expensive Copy)
        if Raw in pkt:
            flow['payloads'].append(bytes(pkt[Raw].load))
        else:
            flow['payloads'].append(b"")
            
        flow['last_time'] = timestamp

    def extract_unsw_features(self, flow_key):
        flow = self.flows[flow_key]
        features = {}

        # 1. Flow Features (Math)
        # Cost: Low (Basic arithmetic)
        def calc_flow_feats():
            dur = max(flow['last_time'] - flow['start_time'], 0.000001)
            return {
                'dur': dur,
                'proto': flow['proto'],
                'sbytes': flow['sbytes'], 'dbytes': flow['dbytes'],
                'spkts': flow['spkts'], 'dpkts': flow['dpkts'],
                'sload': (flow['sbytes'] * 8) / dur,
                'dload': (flow['dbytes'] * 8) / dur,
                'smean': flow['sbytes'] / flow['spkts'] if flow['spkts'] else 0,
                'dmean': flow['dbytes'] / flow['dpkts'] if flow['dpkts'] else 0
            }
        features.update(self.measure_block('Flow_Features', calc_flow_feats))

        # 2. Basic Features (Math + List Iteration)
        # Cost: Medium (Requires iterating lists to separate Source/Dest values)
        def calc_basic_feats():
            # Must separate TTLs and Jitter by direction
            sttls, dttls = [], []
            s_ts, d_ts = [], []
            
            # Manual Iteration O(N)
            for i, d in enumerate(flow['directions']):
                if d == 0: # Source
                    sttls.append(flow['ttls'][i])
                    s_ts.append(flow['timestamps'][i])
                else: # Dest
                    dttls.append(flow['ttls'][i])
                    d_ts.append(flow['timestamps'][i])
            
            # Jitter Calc
            s_jit = np.std([s_ts[i+1]-s_ts[i] for i in range(len(s_ts)-1)]) if len(s_ts)>1 else 0
            d_jit = np.std([d_ts[i+1]-d_ts[i] for i in range(len(d_ts)-1)]) if len(d_ts)>1 else 0
            
            return {
                'sttl': int(np.mean(sttls)) if sttls else 0,
                'dttl': int(np.mean(dttls)) if dttls else 0,
                'swin': flow['swin'], 'dwin': flow['dwin'],
                'sjit': s_jit, 'djit': d_jit
            }
        features.update(self.measure_block('Basic_Features', calc_basic_feats))

        # 3. TCP RTT Features (State Logic)
        # Cost: High (Requires specific conditional checks on previous state)
        def calc_rtt_feats():
            # Calculations based on captured state timestamps
            syn_ack = flow['synack_time'] - flow['syn_time'] if flow['synack_time'] > 0 else 0
            ack_dat = flow['ack_time'] - flow['synack_time'] if flow['ack_time'] > 0 else 0
            tcprtt = syn_ack + ack_dat
            return {
                'tcprtt': tcprtt,
                'synack': syn_ack,
                'ackdat': ack_dat
            }
        features.update(self.measure_block('TCP_RTT_Features', calc_rtt_feats))

        # 4. Content Features (Deep Inspection)
        # Cost: VERY HIGH (String searching inside payloads)
        def calc_content_feats():
            is_ftp = 0
            ct_ftp = 0
            ct_http = 0
            
            # Heavy Loop: Inspecting bytes of every packet
            for p in flow['payloads']:
                if not p: continue
                try:
                    payload_str = str(p)
                    # HTTP Check
                    if "GET " in payload_str or "POST " in payload_str:
                        ct_http += 1
                    # FTP Check
                    if "USER " in payload_str and "ftp" in str(flow['dport']):
                        is_ftp = 1
                    if is_ftp and ("PUT " in payload_str or "STOR " in payload_str):
                        ct_ftp += 1
                except: pass
            
            return {
                'ct_flw_http_mthd': ct_http,
                'is_ftp_login': is_ftp,
                'ct_ftp_cmd': ct_ftp
            }
        features.update(self.measure_block('Content_Features', calc_content_feats))

        # 5. Count/State Features (Global Lookup)
        # Cost: Medium-High (Accessing large global dictionaries)
        def calc_count_feats():
            # In a real UNSW extractor, these lookbacks are time-bounded (e.g., last 100ms)
            # Here we approximate with global lifetime counts
            return {
                'ct_srv_src': self.global_src_ip_count[flow['src_ip']],
                'ct_srv_dst': self.global_dst_ip_count[flow['dst_ip']],
                'ct_dst_src_ltm': min(self.global_src_ip_count[flow['src_ip']], self.global_dst_ip_count[flow['dst_ip']]) # Approx
            }
        features.update(self.measure_block('State_Features', calc_count_feats))

        return features
    
    def get_avg_costs(self):
        avg_costs = {}
        for key, total_ns in self.cost_accumulators.items():
            count = self.cost_counts[key]
            if count > 0:
                avg_costs[key] = (total_ns / count) / 1000.0 
        return avg_costs

    def get_all_features(self):
        return [self.extract_unsw_features(fk) for fk in self.flows.keys()]

class PacketToolApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("UNSW-NB15 'Heavy' Feature Cost Analyzer")
        self.geometry("800x600")
        
        self.lbl = ctk.CTkLabel(self, text="UNSW-NB15 Standard Features (100 pkt/flow)", font=("Arial", 18, "bold"))
        self.lbl.pack(pady=10)
        
        self.btn = ctk.CTkButton(self, text="Select PCAP & Analyze", command=self.run_analysis)
        self.btn.pack(pady=20)
        
        self.txt = ctk.CTkTextbox(self, width=700, height=400)
        self.txt.pack(pady=10)

    def log(self, t):
        self.txt.insert("end", t + "\n")
        self.txt.see("end")

    def run_analysis(self):
        pcap = ctk.filedialog.askopenfilename()
        if not pcap: return
        threading.Thread(target=self.process, args=(pcap,), daemon=True).start()

    def process(self, pcap):
        tracker = UNSW_NB15_FlowTracker()
        self.log(f"Processing {os.path.basename(pcap)}...")
        
        for i, pkt in enumerate(PcapReader(pcap)):
            tracker.process_packet(pkt)
            if i % 1000 == 0: self.log(f"Packets: {i}...")
            
        self.log("Extracting UNSW Features...")
        tracker.get_all_features()
        
        costs = tracker.get_avg_costs()
        
        # Save Cost Report
        data = []
        for group, cost in costs.items():
            data.append({'Feature_Group': group, 'Avg_Cost_Microseconds': cost})
            self.log(f"{group}: {cost:.4f} µs")
            
        pd.DataFrame(data).to_csv("UNSW_Heavy_Cost_Analysis.csv", index=False)
        self.log("✓ Saved UNSW_Heavy_Cost_Analysis.csv")

if __name__ == "__main__":
    app = PacketToolApp()
    app.mainloop()
