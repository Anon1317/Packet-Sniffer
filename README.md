[README.md](https://github.com/user-attachments/files/26311126/README.md)
# 🔍 Network Sniffer

> A lightweight, real-time Python network packet sniffer for Windows — built for educational and diagnostic purposes.

---

## ⚙️ Requirements

| Requirement | Detail |
|-------------|--------|
| 🐍 Python | 3.x or higher |
| 🖥️ OS | Windows only |
| 🔐 Privileges | Administrator required |

---

## 🚀 Getting Started

**1. Clone the repository**
```bash
git clone https://github.com/your-username/network-sniffer.git
cd network-sniffer
```

**2. Run as Administrator**
```bash
python sniffer.py
```
> ⚠️ Right-click your terminal → **"Run as Administrator"** before executing.

---

## 📡 What It Captures

| Protocol | Details Shown |
|----------|--------------|
| 🌐 IPv4 | Version, TTL, Source & Destination IP |
| 🔵 TCP | Ports, Sequence, Acknowledgment, Flags |
| 🟡 UDP | Source/Destination Ports, Length |
| 🔴 ICMP | Type, Code, Checksum |

---

## 🖥️ Sample Output
```
IPv4 Packet:
	 - Version: 4, Header Length: 20, TTL: 128
	 - Protocol: 6, Source: 192.168.1.5, Target: 142.250.80.46

	 - TCP Segment:
		 - Source Port: 52341, Destination Port: 443
		 - Sequence: 3849204832, Acknowledgment: 2948302
		 - Flags:
			 - URG: 0, ACK: 1, PSH: 1, RST: 0, SYN: 0, FIN: 0
```

---

## 🛑 Stopping the Sniffer

Press **`Ctrl+C`** at any time to stop.
```
[*] Stopping sniffer...
[*] Socket closed.
```
> ✅ Promiscuous mode is **automatically disabled** on exit — no manual cleanup needed.

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorized diagnostic use only**.
Do not use it to capture traffic on networks you do not own or have explicit permission to monitor.

---

## 📄 License

MIT License — free to use, modify, and distribute.
