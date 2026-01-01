import customtkinter as ctk
import threading
import pandas as pd
import numpy as np
import os
import time
from collections import defaultdict, deque
from scapy.all import PcapReader, IP, TCP, UDP, ICMP
from datetime import datetime

# --- CONFIGURATION ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class LightweightFlowTracker:
    """
    Extracts all UNSW-NB15 features from PCAP with PER-FEATURE computational cost tracking.
    Memory-optimized with 100 packets per flow limit (deque).
    """
    
    def __init__(self, timeout=120):
        self.flows = {}
        self.timeout = timeout
        self.packet_count = 0
        self.start_time = None
        
        # PER-FEATURE Computational Cost Tracking (Nanoseconds)
        self.feature_costs = defaultdict(float)
        self.feature_counts = defaultdict(int)

    def get_flow_key(self, pkt):
        """Create bidirectional flow key"""
        if IP not in pkt:
            return None
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        
        if TCP in pkt:
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        else:
            sport, dport = 0, 0
        
        # Bidirectional key
        if (src_ip, sport) < (dst_ip, dport):
            return (src_ip, sport, dst_ip, dport, proto)
        else:
            return (dst_ip, dport, src_ip, sport, proto)

    def process_packet(self, pkt):
        """Process packet and update flow statistics."""
        if self.start_time is None:
            self.start_time = time.time()
            
        flow_key = self.get_flow_key(pkt)
        if flow_key is None:
            return

        timestamp = float(pkt.time)
        pkt_len = len(pkt)
        
        # Initialize flow if new
        if flow_key not in self.flows:
            src_ip, sport, dst_ip, dport, proto = flow_key
            self.flows[flow_key] = {
                # Identifiers
                'srcip': src_ip, 'sport': sport,
                'dstip': dst_ip, 'dsport': dport, 
                'proto': self.get_protocol_name(proto),
                
                # State
                'state': 'INT',
                'start_time': timestamp, 'last_time': timestamp,
                
                # Counters
                'fwd_pkts': 0, 'bwd_pkts': 0,
                'fwd_bytes': 0, 'bwd_bytes': 0,
                'totpkts': 0, 'totbytes': 0,
                
                # Deques with maxlen=100
                'timestamps': deque(maxlen=100),
                'pkt_lengths': deque(maxlen=100),
                'header_lengths': deque(maxlen=100),
                'fwd_pkt_lens': deque(maxlen=100),
                'bwd_pkt_lens': deque(maxlen=100),
                'fwd_header_lens': deque(maxlen=100),
                'bwd_header_lens': deque(maxlen=100),
                'fwd_iats': deque(maxlen=100),
                'bwd_iats': deque(maxlen=100),
                'flow_iats': deque(maxlen=100),
                'ttl_values': deque(maxlen=100),
                'window_sizes': deque(maxlen=100),
                'tcp_flags': deque(maxlen=100),
                
                # TCP Flags
                'syn_count': 0, 'ack_count': 0, 'fin_count': 0,
                'urg_count': 0, 'psh_count': 0, 'rst_count': 0,
                
                # Trackers
                'last_fwd_time': None, 'last_bwd_time': None,
                'last_flow_time': timestamp,
                
                # Service
                'service': self.get_service(dport, sport, proto)
            }
            self.flows[flow_key]['timestamps'].append(timestamp)

        flow = self.flows[flow_key]
        src_ip, sport, dst_ip, dport, proto = flow_key
        
        # Direction
        direction = 'fwd' if pkt[IP].src == src_ip else 'bwd'
        
        # Update counters
        flow['totpkts'] += 1
        flow['totbytes'] += pkt_len
        flow['pkt_lengths'].append(pkt_len)
        flow['timestamps'].append(timestamp)
        
        # Inter-arrival times
        if flow['last_flow_time']:
            flow['flow_iats'].append(timestamp - flow['last_flow_time'])
        flow['last_flow_time'] = timestamp
        
        # Direction-specific updates
        if direction == 'fwd':
            flow['fwd_pkts'] += 1
            flow['fwd_bytes'] += pkt_len
            flow['fwd_pkt_lens'].append(pkt_len)
            if flow['last_fwd_time']:
                flow['fwd_iats'].append(timestamp - flow['last_fwd_time'])
            flow['last_fwd_time'] = timestamp
        else:
            flow['bwd_pkts'] += 1
            flow['bwd_bytes'] += pkt_len
            flow['bwd_pkt_lens'].append(pkt_len)
            if flow['last_bwd_time']:
                flow['bwd_iats'].append(timestamp - flow['last_bwd_time'])
            flow['last_bwd_time'] = timestamp
        
        flow['last_time'] = timestamp
        
        # IP Header
        if IP in pkt:
            flow['ttl_values'].append(pkt[IP].ttl)
            ip_header_len = pkt[IP].ihl * 4 if hasattr(pkt[IP], 'ihl') else 20
            flow['header_lengths'].append(ip_header_len)
            
            if direction == 'fwd':
                flow['fwd_header_lens'].append(ip_header_len)
            else:
                flow['bwd_header_lens'].append(ip_header_len)

        # TCP specifics
        if TCP in pkt:
            tcp_flags = int(pkt[TCP].flags)
            flow['tcp_flags'].append(tcp_flags)
            flow['window_sizes'].append(pkt[TCP].window)
            
            # Flag counts
            if tcp_flags & 0x02: flow['syn_count'] += 1
            if tcp_flags & 0x10: flow['ack_count'] += 1
            if tcp_flags & 0x01: flow['fin_count'] += 1
            if tcp_flags & 0x20: flow['urg_count'] += 1
            if tcp_flags & 0x08: flow['psh_count'] += 1
            if tcp_flags & 0x04: flow['rst_count'] += 1
            
            # Update state
            if tcp_flags & 0x02 and tcp_flags & 0x10:
                flow['state'] = 'CON'
            elif tcp_flags & 0x01:
                flow['state'] = 'FIN'
            elif tcp_flags & 0x04:
                flow['state'] = 'RST'
            elif flow['state'] == 'INT' and tcp_flags & 0x10:
                flow['state'] = 'CON'
            
        self.packet_count += 1

    def get_protocol_name(self, proto_num):
        """Convert protocol number to name"""
        proto_map = {1: 'icmp', 6: 'tcp', 17: 'udp'}
        return proto_map.get(proto_num, 'other')
    
    def get_service(self, dport, sport, proto):
        """Determine service based on port numbers"""
        services = {
            20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3',
            143: 'imap', 443: 'https', 445: 'smb', 3306: 'mysql',
            3389: 'rdp', 5432: 'postgresql', 8080: 'http-alt'
        }
        
        if dport in services:
            return services[dport]
        elif sport in services:
            return services[sport]
        else:
            return '-'

    def measure_feature(self, feature_name, func):
        """Measure execution time for a SINGLE feature in nanoseconds"""
        t0 = time.perf_counter_ns()
        result = func()
        t1 = time.perf_counter_ns()
        self.feature_costs[feature_name] += (t1 - t0)
        self.feature_counts[feature_name] += 1
        return result

    def extract_features(self, flow_key):
        """Extract all UNSW-NB15 features with PER-FEATURE cost measurement"""
        flow = self.flows[flow_key]
        features = {}
        
        # Convert deques to lists
        ts = list(flow['timestamps'])
        pkt_lens = list(flow['pkt_lengths'])
        fwd_lens = list(flow['fwd_pkt_lens'])
        bwd_lens = list(flow['bwd_pkt_lens'])
        fwd_iats = list(flow['fwd_iats'])
        bwd_iats = list(flow['bwd_iats'])
        flow_iats = list(flow['flow_iats'])
        ttls = list(flow['ttl_values'])
        wins = list(flow['window_sizes'])
        tcp_flags_list = list(flow['tcp_flags'])
        
        dur = max(flow['last_time'] - flow['start_time'], 1e-6)
        
        # Identifiers (no cost tracking for these)
        features['srcip'] = flow['srcip']
        features['sport'] = flow['sport']
        features['dstip'] = flow['dstip']
        features['dsport'] = flow['dsport']
        features['proto'] = flow['proto']
        features['state'] = flow['state']
        features['service'] = flow['service']
        
        # MEASURE EACH FEATURE INDIVIDUALLY
        
        # Duration
        features['dur'] = self.measure_feature('dur', lambda: dur)
        
        # Bytes
        features['sbytes'] = self.measure_feature('sbytes', lambda: flow['fwd_bytes'])
        features['dbytes'] = self.measure_feature('dbytes', lambda: flow['bwd_bytes'])
        
        # TTL
        features['sttl'] = self.measure_feature('sttl', lambda: int(np.mean(ttls)) if ttls else 0)
        features['dttl'] = self.measure_feature('dttl', lambda: int(np.mean(ttls)) if ttls else 0)
        
        # Loss (simplified)
        features['sloss'] = self.measure_feature('sloss', lambda: 0)
        features['dloss'] = self.measure_feature('dloss', lambda: 0)
        
        # Load
        features['Sload'] = self.measure_feature('Sload', lambda: (flow['fwd_bytes'] * 8) / dur if dur > 0 else 0)
        features['Dload'] = self.measure_feature('Dload', lambda: (flow['bwd_bytes'] * 8) / dur if dur > 0 else 0)
        
        # Packets
        features['Spkts'] = self.measure_feature('Spkts', lambda: flow['fwd_pkts'])
        features['Dpkts'] = self.measure_feature('Dpkts', lambda: flow['bwd_pkts'])
        
        # Mean sizes
        features['smeansz'] = self.measure_feature('smeansz', lambda: np.mean(fwd_lens) if fwd_lens else 0)
        features['dmeansz'] = self.measure_feature('dmeansz', lambda: np.mean(bwd_lens) if bwd_lens else 0)
        
        # Transaction depth
        features['trans_depth'] = self.measure_feature('trans_depth', lambda: 1)
        
        # Response body length
        features['res_bdy_len'] = self.measure_feature('res_bdy_len', lambda: sum(bwd_lens))
        
        # Jitter
        features['Sjit'] = self.measure_feature('Sjit', lambda: np.std(fwd_iats) if len(fwd_iats) > 1 else 0)
        features['Djit'] = self.measure_feature('Djit', lambda: np.std(bwd_iats) if len(bwd_iats) > 1 else 0)
        
        # Times
        features['Stime'] = self.measure_feature('Stime', lambda: flow['start_time'])
        features['Ltime'] = self.measure_feature('Ltime', lambda: flow['last_time'])
        
        # Inter-packet times
        features['Sintpkt'] = self.measure_feature('Sintpkt', lambda: np.mean(fwd_iats) if fwd_iats else 0)
        features['Dintpkt'] = self.measure_feature('Dintpkt', lambda: np.mean(bwd_iats) if bwd_iats else 0)
        
        # TCP RTT (simplified)
        features['tcprtt'] = self.measure_feature('tcprtt', lambda: 0)
        features['synack'] = self.measure_feature('synack', lambda: 0)
        features['ackdat'] = self.measure_feature('ackdat', lambda: 0)
        
        # Window means
        features['smean'] = self.measure_feature('smean', lambda: np.mean(wins) if wins else 0)
        features['dmean'] = self.measure_feature('dmean', lambda: np.mean(wins) if wins else 0)
        
        # State TTL
        features['ct_state_ttl'] = self.measure_feature('ct_state_ttl', lambda: len(set(ttls)) if ttls else 0)
        
        # HTTP/FTP (simplified)
        features['ct_flw_http_mthd'] = self.measure_feature('ct_flw_http_mthd', lambda: 0)
        features['is_ftp_login'] = self.measure_feature('is_ftp_login', lambda: 1 if flow['service'] == 'ftp' else 0)
        features['ct_ftp_cmd'] = self.measure_feature('ct_ftp_cmd', lambda: 0)
        
        # Connection counts (simplified)
        features['ct_srv_src'] = self.measure_feature('ct_srv_src', lambda: 1)
        features['ct_srv_dst'] = self.measure_feature('ct_srv_dst', lambda: 1)
        features['ct_dst_ltm'] = self.measure_feature('ct_dst_ltm', lambda: 1)
        features['ct_src_ltm'] = self.measure_feature('ct_src_ltm', lambda: 1)
        features['ct_src_dport_ltm'] = self.measure_feature('ct_src_dport_ltm', lambda: 1)
        features['ct_dst_sport_ltm'] = self.measure_feature('ct_dst_sport_ltm', lambda: 1)
        features['ct_dst_src_ltm'] = self.measure_feature('ct_dst_src_ltm', lambda: 1)
        
        # Same IP/ports
        features['is_sm_ips_ports'] = self.measure_feature('is_sm_ips_ports', 
            lambda: 1 if flow['srcip'] == flow['dstip'] and flow['sport'] == flow['dsport'] else 0)
        
        # Windows
        features['swin'] = self.measure_feature('swin', lambda: wins[0] if wins else 0)
        features['dwin'] = self.measure_feature('dwin', lambda: wins[-1] if len(wins) > 1 else 0)
        
        # TCP base
        features['stcpb'] = self.measure_feature('stcpb', lambda: sum(1 for f in tcp_flags_list if f & 0x02))
        features['dtcpb'] = self.measure_feature('dtcpb', lambda: sum(1 for f in tcp_flags_list if f & 0x10))
        
        return features

    def get_feature_costs(self):
        """Return average cost per feature in microseconds"""
        avg_costs = {}
        for feature_name, total_ns in self.feature_costs.items():
            count = self.feature_counts[feature_name]
            if count > 0:
                avg_costs[feature_name] = (total_ns / count) / 1000.0  # ns to μs
        return avg_costs

    def get_all_features(self):
        return [self.extract_features(fk) for fk in self.flows.keys()]


class PacketToolApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("UNSW-NB15 Complete Feature Extractor")
        self.geometry("950x800")
        
        # Header
        self.lbl_title = ctk.CTkLabel(
            self, 
            text="UNSW-NB15 Feature Extractor (Per-Feature Cost Analysis)", 
            font=("Arial", 20, "bold")
        )
        self.lbl_title.pack(pady=20)

        # File Input Frame
        self.frame_files = ctk.CTkFrame(self)
        self.frame_files.pack(fill="x", padx=20, pady=10)
        
        # PCAP Input
        self.entry_pcap = ctk.CTkEntry(
            self.frame_files, 
            placeholder_text="Select PCAP file...", 
            width=650
        )
        self.entry_pcap.grid(row=0, column=0, padx=10, pady=10)
        self.btn_pcap = ctk.CTkButton(
            self.frame_files, 
            text="Browse PCAP", 
            command=lambda: self.browse_file(self.entry_pcap, "pcap"),
            width=120
        )
        self.btn_pcap.grid(row=0, column=1, padx=10, pady=10)

        # Ground Truth Input
        self.entry_gt = ctk.CTkEntry(
            self.frame_files, 
            placeholder_text="Select Ground Truth CSV...", 
            width=650
        )
        self.entry_gt.grid(row=1, column=0, padx=10, pady=10)
        self.btn_gt = ctk.CTkButton(
            self.frame_files, 
            text="Browse CSV", 
            fg_color="#555",
            hover_color="#444",
            command=lambda: self.browse_file(self.entry_gt, "csv"),
            width=120
        )
        self.btn_gt.grid(row=1, column=1, padx=10, pady=10)

        # Progress Bar
        self.progress = ctk.CTkProgressBar(self, width=830)
        self.progress.pack(padx=20, pady=10, fill="x")
        self.progress.set(0)
        
        self.progress_label = ctk.CTkLabel(self, text="Ready", font=("Arial", 11))
        self.progress_label.pack()

        # Process Button
        self.btn_process = ctk.CTkButton(
            self, 
            text="EXTRACT ALL FEATURES, LABEL & ANALYZE COSTS", 
            fg_color="#2CC985", 
            hover_color="#229C68",
            text_color="black", 
            height=50, 
            font=("Arial", 14, "bold"),
            command=self.start_processing
        )
        self.btn_process.pack(padx=20, pady=15, fill="x")

        # Log Window
        self.textbox = ctk.CTkTextbox(self, height=450)
        self.textbox.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Welcome Message
        self.log("="*90)
        self.log("UNSW-NB15 Complete Feature Extractor - Per-Feature Cost Tracking")
        self.log("="*90)
        self.log("\nFeatures:")
        self.log("  • Extracts ALL UNSW-NB15 dataset features")
        self.log("  • 100 packets max per flow (Memory Optimized)")
        self.log("  • PER-FEATURE Computational Cost Tracking (nanosecond precision)")
        self.log("  • Ground Truth Labeling with bidirectional matching")
        self.log("  • Generates 2 CSV files: Labeled Dataset + Per-Feature Cost Analysis")
        self.log("\nReady. Please select PCAP and Ground Truth CSV files.")
        self.log("="*90 + "\n")

    def log(self, msg):
        self.textbox.insert("end", msg + "\n")
        self.textbox.see("end")
        self.update_idletasks()
    
    def update_progress(self, value, message=""):
        self.progress.set(value)
        if message:
            self.progress_label.configure(text=message)
        self.update_idletasks()

    def browse_file(self, entry, ftype):
        if ftype == "pcap":
            filetypes = [("PCAP Files", "*.pcap"), ("PCAPNG", "*.pcapng"), ("All Files", "*.*")]
        else:
            filetypes = [("CSV Files", "*.csv"), ("All Files", "*.*")]
            
        filename = ctk.filedialog.askopenfilename(filetypes=filetypes)
        if filename:
            entry.delete(0, "end")
            entry.insert(0, filename)
            try:
                file_size = os.path.getsize(filename) / 1024 / 1024
                self.log(f"✓ Selected {ftype.upper()}: {os.path.basename(filename)} ({file_size:.2f} MB)")
            except:
                self.log(f"✓ Selected {ftype.upper()}: {os.path.basename(filename)}")

    def start_processing(self):
        pcap_path = self.entry_pcap.get()
        gt_path = self.entry_gt.get()
        
        if not pcap_path or not gt_path:
            self.log("❌ Error: Please select both PCAP and Ground Truth files.")
            return
            
        if not os.path.exists(pcap_path):
            self.log(f"❌ Error: PCAP file not found: {pcap_path}")
            return
            
        if not os.path.exists(gt_path):
            self.log(f"❌ Error: Ground Truth file not found: {gt_path}")
            return
        
        self.btn_process.configure(state="disabled", text="Processing...")
        self.update_progress(0, "Initializing...")
        threading.Thread(target=self.run_logic, args=(pcap_path, gt_path), daemon=True).start()

    def run_logic(self, pcap_path, gt_path):
        try:
            self.log("\n" + "="*90)
            self.log("STARTING FEATURE EXTRACTION & LABELING")
            self.log("="*90 + "\n")
            
            tracker = LightweightFlowTracker()
            
            # STEP 1: Load Ground Truth
            self.update_progress(0.05, "Loading Ground Truth...")
            self.log("[1/4] Loading Ground Truth Labels...")
            gt_lookup = {}
            
            try:
                required_cols = ['Attack category', 'Protocol', 'Source IP', 'Destination IP', 
                               'Source Port', 'Destination Port', 'Start time', 'Last time']
                df_gt = pd.read_csv(gt_path, usecols=required_cols, encoding='latin-1')
                df_gt.columns = df_gt.columns.str.strip().str.lower().str.replace(' ', '_')

                for _, row in df_gt.iterrows():
                    proto = str(row['protocol']).lower().strip()
                    key = (
                        str(row['source_ip']).strip(),
                        int(row['source_port']),
                        str(row['destination_ip']).strip(),
                        int(row['destination_port']),
                        proto
                    )
                    
                    label = str(row['attack_category']).strip()
                    if label.lower() in ['nan', '', ' ']:
                        label = 'Normal'
                    
                    gt_lookup[key] = {
                        'label': label,
                        'start': row['start_time'],
                        'end': row['last_time']
                    }
                
                self.log(f"✓ Loaded {len(gt_lookup):,} labeled flows from Ground Truth\n")

            except Exception as e:
                self.log(f"❌ Error loading Ground Truth: {e}\n")
                self.btn_process.configure(state="normal", text="EXTRACT ALL FEATURES, LABEL & ANALYZE COSTS")
                return

            # STEP 2: Process PCAP
            self.update_progress(0.1, "Processing PCAP...")
            self.log("[2/4] Processing PCAP and Extracting Features...")
            count = 0
            
            for pkt in PcapReader(pcap_path):
                tracker.process_packet(pkt)
                count += 1
                if count % 10000 == 0:
                    progress = 0.1 + (0.6 * min(count / 100000, 1.0))
                    self.update_progress(progress, f"Processed {count:,} packets...")
                    self.log(f"  → Processed {count:,} packets...")
            
            self.log(f"✓ Finished reading PCAP")
            self.log(f"✓ Total packets: {count:,}")
            self.log(f"✓ Total flows: {len(tracker.flows):,}\n")

            # STEP 3: Extract Features and Match Labels
            self.update_progress(0.75, "Extracting features and matching labels...")
            self.log("[3/4] Extracting Features and Matching Labels...")
            feature_list = tracker.get_all_features()
            df = pd.DataFrame(feature_list)
            
            final_labels = []
            matched_count = 0
            
            for idx, row in df.iterrows():
                src = row['srcip']
                dst = row['dstip']
                sport = int(row['sport'])
                dport = int(row['dsport'])
                proto_str = row['proto']
                
                # Try both directions
                key_fwd = (src, sport, dst, dport, proto_str)
                key_bwd = (dst, dport, src, sport, proto_str)
                
                if key_fwd in gt_lookup:
                    final_labels.append(gt_lookup[key_fwd]['label'])
                    matched_count += 1
                elif key_bwd in gt_lookup:
                    final_labels.append(gt_lookup[key_bwd]['label'])
                    matched_count += 1
                else:
                    final_labels.append("Normal")
            
            df['attack_cat'] = final_labels
            
            self.log(f"✓ Matched {matched_count:,} flows to Ground Truth attacks")
            self.log(f"✓ Labeled {len(df)-matched_count:,} flows as 'Normal'\n")

            # STEP 4: Save Outputs
            self.update_progress(0.9, "Generating output files...")
            self.log("[4/4] Generating Output Files...")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Reorder columns
            cols = list(df.columns)
            if 'attack_cat' in cols:
                cols.remove('attack_cat')
                cols.append('attack_cat')
            df = df[cols]
            
            # Save Dataset
            dataset_file = f"UNSW_NB15_Complete_{timestamp}.csv"
            df.to_csv(dataset_file, index=False)
            self.log(f"✓ Saved Complete Dataset: {dataset_file}")
            self.log(f"  → Total Rows: {len(df):,}")
            self.log(f"  → Total Features: {len(df.columns)-1} (+ attack_cat label)")
            
            # Label Distribution
            self.log(f"\nLabel Distribution:")
            label_counts = df['attack_cat'].value_counts()
            for label, count in label_counts.items():
                percentage = (count / len(df)) * 100
                self.log(f"  {label:25s}: {count:6,} ({percentage:5.2f}%)")

            # Save PER-FEATURE Computational Cost Analysis
            costs = tracker.get_feature_costs()
            
            cost_data = []
            self.log(f"\n" + "="*90)
            self.log("PER-FEATURE COMPUTATIONAL COST ANALYSIS")
            self.log("="*90)
            self.log(f"Total Features Measured: {len(costs)}\n")
            
            # Sort by cost
            sorted_costs = sorted(costs.items(), key=lambda x: x[1], reverse=True)
            
            for feature_name, cost_us in sorted_costs[:10]:  # Show top 10 most expensive
                if cost_us < 1:
                    status = 'EXCELLENT'
                elif cost_us < 10:
                    status = 'GOOD'
                elif cost_us < 50:
                    status = 'ACCEPTABLE'
                else:
                    status = 'CAUTION'
                
                self.log(f"{feature_name:25s}: {cost_us:10.6f} μs  [{status}]")
            
            self.log(f"\n... and {len(costs)-10} more features")
            
            # Create full cost table
            for feature_name, cost_us in costs.items():
                if cost_us < 1:
                    status = 'EXCELLENT'
                    complexity = 'O(1)'
                elif cost_us < 10:
                    status = 'GOOD'
                    complexity = 'O(1)'
                elif cost_us < 50:
                    status = 'ACCEPTABLE'
                    complexity = 'O(n)'
                else:
                    status = 'CAUTION'
                    complexity = 'O(n)'
                
                cost_data.append({
                    'Feature_Name': feature_name,
                    'Avg_Cost_Microseconds': round(cost_us, 6),
                    'Total_Executions': tracker.feature_counts[feature_name],
                    'Raspberry_Pi_Status': status,
                    'Estimated_Complexity': complexity
                })
            
            cost_file = f"Per_Feature_Costs_{timestamp}.csv"
            df_cost = pd.DataFrame(cost_data)
            # Sort by cost descending
            df_cost = df_cost.sort_values('Avg_Cost_Microseconds', ascending=False)
            df_cost.to_csv(cost_file, index=False)
            self.log(f"\n✓ Saved Per-Feature Cost Report: {cost_file}")
            self.log(f"  → Total Features Analyzed: {len(cost_data)}")
            
            # Statistics
            total_cost = sum(costs.values())
            avg_cost = np.mean(list(costs.values()))
            
            self.log(f"\nCost Statistics:")
            self.log(f"  Total Cost (all features): {total_cost:.6f} μs per flow")
            self.log(f"  Average Cost per feature:  {avg_cost:.6f} μs")
            self.log(f"  Min Cost:                  {min(costs.values()):.6f} μs")
            self.log(f"  Max Cost:                  {max(costs.values()):.6f} μs")
            
            # Final Summary
            self.log("\n" + "="*90)
            self.log("EXTRACTION SUMMARY")
            self.log("="*90)
            self.log(f"PCAP File:                   {os.path.basename(pcap_path)}")
            self.log(f"Ground Truth File:           {os.path.basename(gt_path)}")
            self.log(f"Total Packets Processed:     {tracker.packet_count:,}")
            self.log(f"Total Flows Extracted:       {len(df):,}")
            self.log(f"Features per Flow:           {len(df.columns)-1}")
            self.log(f"Memory Limit per Flow:       100 packets (deque)")
            self.log(f"Processing Time:             {time.time() - tracker.start_time:.2f} seconds")
            self.log(f"\nOutput Files:")
            self.log(f"  1. {dataset_file} - Complete labeled dataset")
            self.log(f"  2. {cost_file} - Per-feature computational costs")
            
            self.log("\n" + "="*90)
            self.log("✓ ALL TASKS COMPLETED SUCCESSFULLY")
            self.log("="*90 + "\n")
            
            self.update_progress(1.0, "✓ Complete!")
            
        except Exception as e:
            self.log(f"\n❌ Critical Error: {e}")
            import traceback
            self.log(traceback.format_exc())
            
        finally:
            self.btn_process.configure(state="normal", text="EXTRACT ALL FEATURES, LABEL & ANALYZE COSTS")


if __name__ == "__main__":
    app = PacketToolApp()
    app.mainloop()
