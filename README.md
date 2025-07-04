# 🛡️ Mini-NIDS: Basic Network Intrusion Detection System

A lightweight Python-based tool that monitors network traffic in real time and detects port scanning behavior. Built using `scapy`, this CLI-based NIDS is ideal for learning and basic intrusion detection demonstrations.

---

## 🔍 Features

- 📡 Real-time packet sniffing using `scapy`
- 🧠 Detects TCP SYN scan attempts (common in Nmap and stealth scanning)
- 🚨 Raises alerts when an IP probes more than 10 different ports
- 🎨 Colored terminal output with timestamps using `colorama`
- 💻 Cross-platform (with dependencies like `Npcap` on Windows)

---

## 🛠️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/soumikdas07/mini-nids.git
cd mini-nids
