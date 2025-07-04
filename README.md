# 🛡️ Mini-NIDS: Network Intrusion Detection System

A lightweight, CLI-based Python tool that detects port scanning behavior in real time using raw packet sniffing. Built with `scapy`, this educational NIDS flags suspicious SYN scan patterns, like those used in Nmap stealth scans.

---

## ⚙️ Features

- 📡 **Live TCP packet sniffing** with `scapy`
- 🚨 **Real-time detection** of port scans using TCP SYN flags
- 📊 Alerts when one IP probes more than **10 unique ports**
- 🎨 Colored CLI output using `colorama`
- 🧠 Minimal, readable, beginner-friendly code
- 🪶 Cross-platform support (requires Npcap on Windows)

---

## 🚀 How to Run

### 1. Clone the Repository

```bash
git clone https://github.com/soumikdas07/mini-nids.git
cd mini-nids
```
### 2. Install Dependencies
```pip install -r requirements.txt```

### 3. Start the Detector
```python nids.py```
### 4. Terminal output:
```[*] Mini-NIDS is running... Press Ctrl+C to stop.```
### 5. Simulate an Attack (Test It)
```
nmap -sS 127.0.0.1
This triggers SYN packets to multiple ports. When the threshold is crossed, Mini-NIDS will alert:
[ALERT] 127.0.0.1 is scanning ports on 127.0.0.1 | Ports: 12 | Time: 10:29:31
```



