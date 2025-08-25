## DOS Detection

In order to detect DOS (Denial of Service) attacks, we have to **intercept, monitor, analyze, and output** whether the incoming traffic shows a normal pattern or an abnormal one indicative of an attack.
### Approach

1. **Packet Capture**  
    Capture incoming network packets on a given network interface. This gives us access to real-time traffic.
    
2. **Traffic Monitoring & Analysis**  
    Continuously monitor the number of requests (or packets) per source IP within a given time frame.
    
3. **Pattern Detection**  
    If the number of packets from a single IP or overall traffic exceeds a threshold in a short period, flag it as a potential DOS attack.
    
4. **Output & Alert**  
    Display a warning or log it if an attack is detected.
    

---
### Libraries Used

- **scapy**  
    For packet sniffing, crafting, and manipulation.  
    We will use it to **capture network packets** and extract **source IPs**.
    
- **collections  
    Built-in Python library with most common data structures.
    
- **time**  
    To track traffic **over intervals** (sliding window technique).
    
- **threading**  
    To **run packet sniffing and analysis simultaneously** without blocking.
    
- **math**
    Important Mathematical functions such as **Log**
    
- **statistics**
    Important Statistical functions such as **mean, standard deviation and variance** to estimate and judge the pattern

---

### Code and Explanation

#### 1. Import Libraries

```python
from scapy.all import sniff
from collections import Counter
import time
import threading
```

- `sniff` → captures packets on an interface.
    
- `Counter` → counts the number of packets per IP.
    
- `time` → for timestamps and intervals.
    
- `threading` → runs monitoring logic without interrupting sniffing.
    

---
#### 2. Global Variables

```python
packet_counts = Counter()
threshold = 100  # Example: more than 100 packets in 10 seconds = alert
interval = 10    # Every 10 seconds
```

- `packet_counts` → stores how many packets each IP sent.
    
- `threshold` → defines what is considered **abnormal traffic**.
    
- `interval` → the time window for monitoring.

---
#### 3. Packet Capture Function

```python
def process_packet(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        packet_counts[src_ip] += 1
```

- **What it does:**  
    Every time a packet is captured, it checks if the packet has an IP layer, extracts the **source IP**, and increments its count.

---
#### 4. Monitoring Function

```python
def monitor_traffic():
    while True:
        time.sleep(interval)
        print("Traffic Summary:", packet_counts)
        for ip, count in packet_counts.items():
            if count > threshold:
                print(f"[ALERT] Possible DOS attack from IP: {ip} with {count} packets in {interval}s")
        packet_counts.clear()
```

- **What it does:**  
    Every `interval` seconds:
    
    - Prints traffic summary.
        
    - Checks if any IP exceeded the threshold.
        
    - Clears counts for the next interval.
    

---
#### 5. Start Sniffing and Monitoring

```python
if __name__ == "__main__":
    t = threading.Thread(target=monitor_traffic)
    t.daemon = True
    t.start()
    sniff(prn=process_packet, store=False)
```

- Starts a separate thread for monitoring.
    
- `sniff()` runs in the main thread to capture packets and call `process_packet()`.

**Note:** I can't explain the code as it will take tremendous time, Just explained the important functions. 

---
### How It Detects DOS

- **Normal Behavior:**  
    Multiple IPs sending a moderate number of packets → below threshold.
    
- **DOS Behavior:**  
    One IP or a small group sending an extremely high number of packets within a short interval → flagged as abnormal.

---
### Code:

```python
from scapy.all import sniff, TCP, UDP, IP, ICMP
from collections import defaultdict, deque
import time, math, statistics as stats

WINDOW = 1.0
HIST = 120
MIN_BASELINE = 20

state = {
    "bucket_start": time.time(),
    "pkts": 0,
    "bytes": 0,
    "tcp_syn": 0,
    "tcp_synack": 0,
    "tcp_ack": 0,
    "tcp_ack_only": 0,
    "tcp_fin": 0,
    "tcp_rst": 0,
    "icmp_echo_req": 0,
    "icmp_echo_rep": 0,
    "udp_pkts": 0,
    "src_ips": set(),
    "udp_dst_ports": set(),
}

history = defaultdict(lambda: deque(maxlen=HIST))

def shannon_entropy(values):
    if not values:
        return 0.0
    counts = defaultdict(int)
    for v in values: counts[v]+=1
    n = len(values)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log(p, 2)
    return ent

def push_feature(name, value):
    history[name].append(value)

def baseline_anomaly(name, current, k=4.0):
    # z-score anomaly vs baseline
    h = list(history[name])
    if len(h) < MIN_BASELINE:
        return False, f"{name}: warming-up"
    mu = stats.mean(h)
    sd = stats.pstdev(h) or 1.0
    z = (current - mu) / sd
    return z >= k, f"{name}: curr={current:.1f} μ={mu:.1f} σ={sd:.1f} z={z:.1f}"

def finalize_bucket():
    now = time.time()
    duration = now - bucket_start()
    if duration <= 0: return
    pps = state["pkts"] / duration
    bps = state["bytes"] * 8 / duration
    syn_rate = state["tcp_syn"] / duration
    ack_only_rate = state["tcp_ack_only"] / duration
    fin_rate = state["tcp_fin"] / duration
    rst_rate = state["tcp_rst"] / duration
    udp_rate = state["udp_pkts"] / duration
    icmp_req_rate = state["icmp_echo_req"] / duration
    syn_ack_ratio = (state["tcp_synack"] / state["tcp_syn"]) if state["tcp_syn"] else 1.0
    unique_src = len(state["src_ips"])
    udp_ports = len(state["udp_dst_ports"])
    src_entropy = shannon_entropy(list(state["src_ips"]))
    # Push to history
    for k, v in [
        ("pps", pps), ("bps", bps), ("syn_rate", syn_rate),
        ("ack_only_rate", ack_only_rate), ("fin_rate", fin_rate),
        ("rst_rate", rst_rate), ("udp_rate", udp_rate),
        ("icmp_req_rate", icmp_req_rate), ("syn_ack_ratio", syn_ack_ratio),
        ("unique_src", unique_src), ("udp_ports", udp_ports),
        ("src_entropy", src_entropy)
    ]: push_feature(k, v)
    alerts = []
    # SYN flood: high SYN rate and low SYN/ACK ratio
    if syn_rate > 2000 or (syn_rate > 500 and syn_ack_ratio < 0.3):
        alerts.append(f"[SYN-FLOOD] syn_rate={syn_rate:.0f}/s syn_ack_ratio={syn_ack_ratio:.2f}")
    if ack_only_rate > 2000:
        alerts.append(f"[ACK-FLOOD] ack_only_rate={ack_only_rate:.0f}/s")
    if fin_rate > 1000:
        alerts.append(f"[FIN-FLOOD] fin_rate={fin_rate:.0f}/s")
    if rst_rate > 1000:
        alerts.append(f"[RST-FLOOD] rst_rate={rst_rate:.0f}/s")
    # UDP flood: very high UDP PPS, many dst ports and high src entropy
    if udp_rate > 5000 or (udp_rate > 1500 and udp_ports > 50 and src_entropy > 6.0):
        alerts.append(f"[UDP-FLOOD] udp_rate={udp_rate:.0f}/s ports={udp_ports} srcH={src_entropy:.1f}")
    # ICMP flood: echo req rate much higher than replies
    if icmp_req_rate > 1000:
        alerts.append(f"[ICMP-FLOOD] echo_req_rate={icmp_req_rate:.0f}/s")
    if unique_src > 100 and pps > 1000 and src_entropy > 6.0:
        alerts.append(f"[SRC-RANDOMIZED] unique_src={unique_src} entropy={src_entropy:.1f}")
    for feat in ["pps", "bps", "unique_src"]:
        is_anom, msg = baseline_anomaly(feat, locals()[feat], k=4.0)
        if is_anom:
            alerts.append(f"[ANOMALY] {msg}")
    summary = (f"pps={pps:.0f} bps={bps/1e6:.2f}Mbps syn={state['tcp_syn']} ack_only={state['tcp_ack_only']} "
               f"fin={state['tcp_fin']} rst={state['tcp_rst']} udp={state['udp_pkts']} icmp_req={state['icmp_echo_req']} "
               f"src={unique_src} H(src)={src_entropy:.1f}")
    if alerts:
        print(time.strftime("%H:%M:%S"), "ALERTS:", " | ".join(alerts), "|", summary)
    else:
        print(time.strftime("%H:%M:%S"), summary)
    reset_bucket(now)

def bucket_start():
    return state["bucket_start"]

def reset_bucket(now=None):
    t = now or time.time()
    for k in list(state.keys()):
        if k == "bucket_start": continue
        if isinstance(state[k], set):
            state[k].clear()
        else:
            state[k] = 0
    state["bucket_start"] = t

def on_pkt(pkt):
    try:
        if time.time() - bucket_start() >= WINDOW:
            finalize_bucket()
        if IP in pkt:
            state["pkts"] += 1
            state["bytes"] += len(pkt)
            state["src_ips"].add(pkt[IP].src)
            if TCP in pkt:
                flags = pkt[TCP].flags
                if flags & 0x02 and not (flags & 0x10): # SYN without ACK
                    state["tcp_syn"] += 1
                if (flags & 0x12) == 0x12: # SYN+ACK
                    state["tcp_synack"] += 1
                if flags & 0x10:
                    state["tcp_ack"] += 1
                if flags == 0x10:
                    state["tcp_ack_only"] += 1
                if flags & 0x01:
                    state["tcp_fin"] += 1
                if flags & 0x04:
                    state["tcp_rst"] += 1
            elif UDP in pkt:
                state["udp_pkts"] += 1
                state["udp_dst_ports"].add(pkt[UDP].dport)
            elif ICMP in pkt:
                ic = pkt[ICMP]
                if ic.type == 8: # Echo request
                    state["icmp_echo_req"] += 1
                elif ic.type == 0: # Echo reply
                    state["icmp_echo_rep"] += 1
    except Exception:
        pass

if __name__ == "__main__":
    print("Starting DoS detector (1s windows). Ctrl+C to stop.")
    sniff(prn=on_pkt, store=False)
```
---
Video [Link](https://www.youtube.com/watch?v=l9A795wdPwY)