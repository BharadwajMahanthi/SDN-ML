# SDN-ML: Complete Installation and User Guide

This comprehensive manual covers everything from installation to running advanced attack simulations.

> **✅ Architecture:**
>
> - **Controller:** Floodlight v1.2 (Windows Native)
> - **Network:** Mininet v2.3.1b4 (WSL2 Native)
> - **Connectivity:** Windows Firewall Rules (TCP 6653, 8080)

---

# 📚 Table of Contents

1. [Installation & Setup](#part-1-installation--setup)
2. [Quick Start](#part-2-quick-start)
3. [Manual Data Collection](#part-3-manual-data-collection)
4. [Automated Labeled Collection](#part-4-automated-labeled-collection)
5. [TopoGuard Ground Truth Labeling](#part-5-topoguard-ground-truth-labeling)
6. [Attack Demonstrations](#part-6-attack-demonstrations)
7. [Troubleshooting](#part-7-troubleshooting)

---

# Part 1: Installation & Setup

## 1. Prerequisites

1.  **Windows 10/11** (WSL2 enabled)
2.  **Java JDK 11** -> [Download OpenJDK 11](https://jdk.java.net/java-se-ri/11)
3.  **Apache Ant** -> [Download Apache Ant](https://ant.apache.org/bindownload.cgi)
4.  **Python 3.8+**

## 2. Setup Floodlight (Windows)

```powershell
cd floodlight_with_topoguard
ant
# Run Controller
java -jar target/floodlight.jar
```

## 3. Setup Mininet (WSL2)

Open your WSL2 terminal (Ubuntu):

```bash
# Install Dependencies
sudo apt-get update && sudo apt-get install -y git python3-pip help2man net-tools openvswitch-switch

# Install Mininet
git clone https://github.com/mininet/mininet.git
cd mininet
sudo PYTHON=python3 ./util/install.sh -n

# Start OVS
sudo service openvswitch-switch start
```

## 4. Configure Firewall (Critical)

**Run PowerShell as Administrator:**

```powershell
New-NetFirewallRule -DisplayName "Floodlight OpenFlow" -Direction Inbound -LocalPort 6653 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Floodlight REST API" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
```

---

# Part 2: Quick Start

**Terminal 1 (Windows): Start Floodlight**

```powershell
cd floodlight_with_topoguard
java -jar target/floodlight.jar
```

**Terminal 2 (WSL2): Start Mininet**

```bash
# Find Windows Host IP
grep nameserver /etc/resolv.conf | awk '{print $2}'
# (Assume IP is 10.255.255.254 for example)

# Start Mininet
sudo mn --controller=remote,ip=10.255.255.254,port=6653 --topo single,4
```

**Terminal 3 (Windows): Start Collector**

```powershell
python collect_live_data.py
```

---

# Part 3: Manual Data Collection

Use this method to manually control traffic generation and see the results in real-time.

### Step 1: Generate Traffic in Mininet (WSL2)

```bash
mininet> pingall

# Background Pings
mininet> h1 ping -c 100 h4 &
mininet> h2 ping -c 100 h3 &
```

### Step 2: Run Collector (Windows)

```powershell
python collect_live_data.py
```

You will see:

- `Round 1: ✓ 15 flows...`
- `Round 2: ✓ 18 flows...`
- **Output:** `ml_dataset/sdn_flows_TIMESTAMP.csv`

---

# Part 4: Automated Labeled Collection

Use `collect_labeled_data.py` to automatically create a training dataset with `label=0` (Normal) and `label=1` (Attack).

### 1. Run the Script (Windows)

```powershell
python collect_labeled_data.py
```

### 2. Follow the Prompts

**Scenario 1: Normal Traffic**

- Script Prompt: "Press Enter when ready..."
- Action (Mininet): `h1 ping h4 &`
- Result: Labeled `0`

**Scenario 2: Host Hijack Attack**

- Script Prompt: "Run attack and press Enter..."
- Action (Mininet): `h1 python3 attacker/host_location_hijack.py 10.0.0.2 00:00:00:00:00:99`
- Result: Labeled `1`

**Output:** `ml_dataset/labeled_sdn_data_TIMESTAMP.csv`

---

# Part 5: TopoGuard Ground Truth Labeling

This advanced method uses **TopoGuard's actual security alerts** to label data, providing ground truth.

### Workflow

1.  **Run Floodlight & Mininet** as usual.
2.  **Start Collector** (`collect_live_data.py`).
3.  **Launch Attacks** in Mininet (see Part 6).
4.  **Wait** for TopoGuard to log alerts (check `floodlight.log`).
5.  **Run Labeler:**

```powershell
python topoguard_labeler.py
```

It will:

- Parse `floodlight.log` for alerts
- Correlate with flow timestamps
- Add accurate labels to your CSV

---

# Part 6: Attack Demonstrations

All attack scripts are located in `/attacker/` inside the repo. Run them from **Mininet (WSL2)**.

### 1. Host Location Hijacking

**Concept:** Attacker sends fake ARP to mislead controller about host location.

```bash
# Mininet (h1 acts as attacker)
mininet> h1 python3 attacker/host_location_hijack.py 10.0.0.2 00:00:00:00:00:99
```

**Verification:**

- Floodlight Log: `TopoGuard: Host location inconsistency detected`
- TopoGuard blocks the move.

### 2. Link Fabrication

**Concept:** Fake LLDP packets to create non-existent links.

```bash
mininet> h1 python3 attacker/link_fabrication.py 00:00:00:00:00:99 01:02:03:04:05:06
```

**Verification:**

- Floodlight Log: `TopoGuard: Invalid LLDP packet`
- Topology map remains unchanged.

### 3. DDoS Attack

**Concept:** Flood controller with Packet-In messages.

```bash
mininet> h1 python3 attacker/ddos_attack.py 1 10.0.0.4
```

**Verification:**

- Controller CPU load increases
- Rate limiting engages

---

# Part 7: Troubleshooting

| Issue                                     | Solution                                                                                                        |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **"Unable to contact remote controller"** | 1. Check Floodlight is running.<br>2. Verify Windows IP (`grep nameserver`).<br>3. **Re-apply Firewall rules.** |
| **"Curl failed to connect"**              | Firewall issue. Test with `ping YOUR_WINDOWS_IP` from WSL2.                                                     |
| **"Address already in use"**              | `taskkill /F /IM java.exe`                                                                                      |

### Useful Commands

**Check Floodlight API:**

```powershell
curl http://localhost:8080/wm/core/controller/summary/json
curl http://localhost:8080/wm/core/switch/all/flow/json
```

**Check Mininet/OVS:**

```bash
sudo ovs-vsctl show
sudo mn --test pingall
```
