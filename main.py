import threading
import pandas as pd
import numpy as np
import os
import time
import re
from collections import defaultdict, deque
from scapy.all import PcapReader, IP, TCP, UDP, Raw

# --- CONFIGURATION ---
INPUT_PCAP = "your_traffic.pcap"        # <--- REPLACE WITH YOUR PCAP FILE
GROUND_TRUTH = "your_gt.csv"            # <--- REPLACE WITH YOUR GT CSV
MAX_PACKETS_PER_FLOW = 100              # Strict limit for Raspberry Pi feasibility

class UNSW_FlowTracker:
    """
    Tracks flows and extracts 'Heavy' UNSW-NB15 features.
    Strictly buffers only the last 100 packets per flow.
    """
    
    def __init__(self):
        self.flows = {}
        
        # GLOBAL STATE TABLES (Required for UNSW 'ct_' features)
        # These features are "Heavy" because they need global knowledge of all flows.
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
            
        # Canonical Key (A->B and B->A are same flow)
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
        """Process packet with 100-packet limit."""
        if IP not in pkt: return

        # 1. GLOBAL STATE UPDATES (Expensive O(1) but frequent)
        self.global_src_ip_count[pkt[IP].src] += 1
        self.global_dst_ip_count[pkt[IP].dst] += 1
        
        flow_key = self.get_flow_key(pkt)
        timestamp = float(pkt.time)
        
        if flow_key not in self.flows:
            # Initialize complex flow object
            self.flows[flow_key] = {
                # Basic Identifiers
                'src_ip': pkt[IP].src, 'dst_ip': pkt[IP].dst,
                'sport': 0, 'dport': 0, 'proto': pkt[IP].proto,
                'start_time': timestamp, 'last_time': timestamp,
                
                # LIMITED BUFFERS (Deque maxlen=100)
                'timestamps': deque(maxlen=MAX_PACKETS_PER_FLOW),
                'pkt_sizes': deque(maxlen=MAX_PACKETS_PER_FLOW),
                'directions': deque(maxlen=MAX_PACKETS_PER_FLOW), # 0=Src->Dst, 1=Dst->Src
                'ttls': deque(maxlen=MAX_PACKETS_PER_FLOW),
                'tcp_flags': deque(maxlen=MAX_PACKETS_PER_FLOW),
                'payloads': deque(maxlen=MAX_PACKETS_PER_FLOW),
                
                # Counters
                'sbytes': 0, 'dbytes': 0,
                'spkts': 0, 'dpkts': 0,
                'swin': 0, 'dwin': 0,
                
                # State for TCP RTT
                'syn_time': 0, 'synack_time': 0, 'ack_time': 0 
            }
            
            if TCP in pkt:
                self.flows[flow_key]['sport'] = pkt[TCP].sport
                self.flows[flow_key]['dport'] = pkt[TCP].dport
            elif UDP in pkt:
                self.flows[flow_key]['sport'] = pkt[UDP].sport
                self.flows[flow_key]['dport'] = pkt[UDP].dport

        flow = self.flows[flow_key]
        
        # Determine direction: Creator is "Source", other is "Dest"
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
            # RTT Logic (Stateful)
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

        # Payload extraction (Costly Copy)
        if Raw in pkt:
            flow['payloads'].append(bytes(pkt[Raw].load))
        else:
            flow['payloads'].append(b"")
            
        flow['last_time'] = timestamp

    def extract_features(self, flow_key):
        flow = self.flows[flow_key]
        features = {}
        
        # Pre-calc lists (Costly conversion from deque)
        ts = list(flow['timestamps'])
        dirs = list(flow['directions'])
        ttls = list(flow['ttls'])
        payloads = list(flow['payloads'])

        # --- FEATURE GROUP 1: FLOW ---
        def calc_flow():
            dur = max(flow['last_time'] - flow['start_time'], 0.000001)
            return {
                'dur': dur,
                'spkts': flow['spkts'], 'dpkts': flow['dpkts'],
                'sbytes': flow['sbytes'], 'dbytes': flow['dbytes'],
                'rate': (flow['spkts'] + flow['dpkts']) / dur,
                'sload': (flow['sbytes'] * 8) / dur,
                'dload': (flow['dbytes'] * 8) / dur,
                'smean': flow['sbytes'] / flow['spkts'] if flow['spkts'] else 0,
                'dmean': flow['dbytes'] / flow['dpkts'] if flow['dpkts'] else 0
            }
        features.update(self.measure_block('1_Flow_Features', calc_flow))

        # --- FEATURE GROUP 2: BASIC ---
        def calc_basic():
            # Must manually filter lists by direction (Costly Loop)
            sttls = [ttls[i] for i in range(len(ttls)) if dirs[i] == 0]
            dttls = [ttls[i] for i in range(len(ttls)) if dirs[i] == 1]
            return {
                'sttl': int(np.mean(sttls)) if sttls else 0,
                'dttl': int(np.mean(dttls)) if dttls else 0,
                'swin': flow['swin'], 'dwin': flow['dwin']
            }
        features.update(self.measure_block('2_Basic_Features', calc_basic))

        # --- FEATURE GROUP 3: TIME & JITTER ---
        def calc_jitter():
            # Must separate timestamps by direction to calculate specific jitter
            sts = [ts[i] for i in range(len(ts)) if dirs[i] == 0]
            dts = [ts[i] for i in range(len(ts)) if dirs[i] == 1]
            
            sjit = np.std([sts[i+1]-sts[i] for i in range(len(sts)-1)]) if len(sts)>1 else 0
            djit = np.std([dts[i+1]-dts[i] for i in range(len(dts)-1)]) if len(dts)>1 else 0
            
            sinpkt = np.mean([sts[i+1]-sts[i] for i in range(len(sts)-1)]) if len(sts)>1 else 0
            dinpkt = np.mean([dts[i+1]-dts[i] for i in range(len(dts)-1)]) if len(dts)>1 else 0
            
            return {'sjit': sjit, 'djit': djit, 'sinpkt': sinpkt, 'dinpkt': dinpkt}
        features.update(self.measure_block('3_Time_Features', calc_jitter))

        # --- FEATURE GROUP 4: TCP RTT (Stateful) ---
        def calc_rtt():
            syn_ack = flow['synack_time'] - flow['syn_time'] if flow['synack_time'] > 0 else 0
            ack_dat = flow['ack_time'] - flow['synack_time'] if flow['ack_time'] > 0 else 0
            return {
                'tcprtt': syn_ack + ack_dat,
                'synack': syn_ack,
                'ackdat': ack_dat
            }
        features.update(self.measure_block('4_TCP_RTT_Features', calc_rtt))

        # --- FEATURE GROUP 5: CONTENT (Deep Inspection) ---
        def calc_content():
            is_ftp = 0
            ct_ftp = 0
            ct_http = 0
            
            # Heavy Loop: Inspecting bytes of every packet
            for p in payloads:
                if not p: continue
                try:
                    p_str = str(p)
                    # HTTP Check (Substring Search)
                    if "GET " in p_str or "POST " in p_str:
                        ct_http += 1
                    # FTP Check
                    if "USER " in p_str and "ftp" in str(flow['dport']):
                        is_ftp = 1
                    if is_ftp and ("PUT " in p_str or "STOR " in p_str):
                        ct_ftp += 1
                except: pass
            
            return {
                'ct_flw_http_mthd': ct_http,
                'is_ftp_login': is_ftp,
                'ct_ftp_cmd': ct_ftp
            }
        features.update(self.measure_block('5_Content_Features', calc_content))

        # --- FEATURE GROUP 6: STATE (Global Lookups) ---
        def calc_state():
            # These simulate the "ct_" features that check global connection counts
            return {
                'ct_srv_src': self.global_src_ip_count[flow['src_ip']],
                'ct_srv_dst': self.global_dst_ip_count[flow['dst_ip']],
                'ct_dst_ltm': self.global_dst_ip_count[flow['dst_ip']], # Approx
                'ct_src_ltm': self.global_src_ip_count[flow['src_ip']]  # Approx
            }
        features.update(self.measure_block('6_State_Features', calc_state))

        return features

    def get_avg_costs(self):
        avg_costs = {}
        for key, total_ns in self.cost_accumulators.items():
            count = self.cost_counts[key]
            if count > 0:
                avg_costs[key] = (total_ns / count) / 1000.0 # Convert ns to µs
        return avg_costs

    def get_all_features(self):
        return [self.extract_features(fk) for fk in self.flows.keys()]


# --- MAIN EXECUTION BLOCK ---
if __name__ == "__main__":
    if not os.path.exists(INPUT_PCAP) or not os.path.exists(GROUND_TRUTH):
        print(f"❌ Error: Please ensure '{INPUT_PCAP}' and '{GROUND_TRUTH}' exist.")
        exit()

    print(f"1. Loading Ground Truth from {GROUND_TRUTH}...")
    gt_lookup = {}
    try:
        df_gt = pd.read_csv(GROUND_TRUTH, encoding='latin-1')
        # Normalize columns
        df_gt.columns = df_gt.columns.str.strip().str.lower().str.replace(' ', '_')
        
        for _, row in df_gt.iterrows():
            # Create key: src, sport, dst, dport, proto
            key = (
                str(row['source_ip']).strip(),
                int(row['source_port']),
                str(row['destination_ip']).strip(),
                int(row['destination_port']),
                str(row['protocol']).lower().strip()
            )
            # Label
            label = str(row['attack_category']).strip()
            if label.lower() in ['nan', '', ' ']: label = 'Normal'
            gt_lookup[key] = label
        print(f"   ✓ Loaded {len(gt_lookup)} GT records.")
    except Exception as e:
        print(f"   ❌ Error loading GT: {e}")
        exit()

    print(f"2. Processing PCAP {INPUT_PCAP} (Max 100 pkts/flow)...")
    tracker = UNSW_FlowTracker()
    count = 0
    
    # Process Packets
    try:
        for pkt in PcapReader(INPUT_PCAP):
            tracker.process_packet(pkt)
            count += 1
            if count % 5000 == 0:
                print(f"   Processed {count} packets...", end='\r')
        print(f"\n   ✓ Finished. Total Flows: {len(tracker.flows)}")
    except Exception as e:
        print(f"\n   ❌ Error reading PCAP: {e}")
        exit()

    print("3. Extracting Features & Calculating Costs...")
    features_list = tracker.get_all_features()
    df_features = pd.DataFrame(features_list)

    print("4. Matching Labels...")
    final_labels = []
    matched = 0
    for idx, row in df_features.iterrows():
        # Reconstruct Keys
        src, dst = row.get('src_ip'), row.get('dst_ip')
        # Handle features dict structure (identifiers are not in extract_features return)
        # Note: In this specific script structure, extract_features returns dict without IP.
        # We need to grab them from the flow object or add them to the return.
        # *Correction*: We need to merge keys back.
        # Let's fix this dynamically:
        
        # Get Key from Tracker
        flow_key = list(tracker.flows.keys())[idx]
        src, sport, dst, dport, proto_num = flow_key
        
        # Proto mapping
        proto_str = 'tcp' if proto_num == 6 else ('udp' if proto_num == 17 else 'other')
        
        # Check both directions
        k1 = (str(src), sport, str(dst), dport, proto_str)
        k2 = (str(dst), dport, str(src), sport, proto_str)
        
        if k1 in gt_lookup:
            final_labels.append(gt_lookup[k1])
            matched += 1
        elif k2 in gt_lookup:
            final_labels.append(gt_lookup[k2])
            matched += 1
        else:
            final_labels.append("Normal")
            
    df_features['Label'] = final_labels
    print(f"   ✓ Matched {matched} flows.")

    print("5. Saving Files...")
    # Save Dataset
    df_features.to_csv("UNSW_NB15_Approximated_Features.csv", index=False)
    
    # Save Cost Report
    costs = tracker.get_avg_costs()
    cost_data = [{'Feature_Group': k, 'Avg_Cost_Microseconds': v} for k, v in costs.items()]
    pd.DataFrame(cost_data).to_csv("UNSW_Feature_Costs.csv", index=False)
    
    print("\n✓ DONE!")
    print("  -> 'UNSW_NB15_Approximated_Features.csv'")
    print("  -> 'UNSW_Feature_Costs.csv'")
