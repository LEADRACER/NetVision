# 🌐 NetVision v4.3.0 — Multi-Subnet & Hop-Based Scanning

![NetVision Banner](https://img.shields.io/badge/Version-4.3.0-blue?style=for-the-badge)
![Tech Stack](https://img.shields.io/badge/Stack-FastAPI%20|%20React-green?style=for-the-badge)

## 🚀 What's New

This major update adds **multi-subnet scanning**, **configurable scan durations**, and experimental **hop-based router discovery** to NetVision. The UI has been significantly enhanced with sticky stats, progress indicators, and improved device cards — all while preserving the original Neutral Zinc theme and dot-grid design.

---

### 🌐 Multi-Subnet Scanning

- **ALL SUBNETS Mode:** One-click scanning of the 5 most common private /24 networks:
  - `192.168.0.0/24`
  - `192.168.1.0/24`
  - `192.168.2.0/24`
  - `10.0.0.0/24`
  - `172.16.0.0/24`
- **Custom Target Input:** Enter any CIDR notation (e.g., `192.168.1.0/24`) or specific IP
- **Live Subnet Indicator:** See which subnet is currently being scanned in the sidebar
- **Sequential Scanning:** Subnets are scanned one after another with consolidated results

---

### ⏱️ Configurable Scan Duration

- Choose between **Unlimited** (profile-based), **30 seconds**, or **1 minute**
- Duration automatically adjusts Nmap timeouts:
  - `--host-timeout` set to selected duration
  - `--max-rtt-timeout` scales with duration (min 100ms, max 2s)
- Perfect for quick sweeps or controlled deep scans

---

### 🛣️ Hop-Based Router Scanning (Experimental)

**TRACE HOPS** toggle enables trailblazing feature:
1. Performs ICMP traceroute to target (using scapy)
2. Discovers each router (hop) along the path
3. Determines each router's local /24 subnet
4. Scans **all those network segments** automatically
5. Devices are tagged with `hop_count` (TTL from traceroute)

**Use Cases:**
- Map your entire local network path including intermediate switches/routers
- Discover devices on different VLANs accessible via router
- Understand network topology with hop counts

**Note:** Works best with single target scans (not "All Subnets" mode)

---

### 🎨 UI/UX Enhancements

**Sidebar:**
- Sticky header with live statistics (Nodes count, Open ports total)
- WebSocket connection status (Connected/Connecting/Disconnected)
- Animated scan progress bar
- Refresh button for quick reload
- Last update timestamp
- Target input + ALL SUBNETS button
- TRACE HOPS toggle switch
- Duration dropdown

**Device Cards:**
- **Grid view:** Open port badge, hop count (↗ N), OS preview, vendor, IP
- **Sidebar view:** Open ports count, hop hops away, vulnerability warnings
- Staggered fade-in entrance animations
- Hover effects with subtle elevation

**Details Overlay:**
- Increased width (480px) for better readability
- Stats grid: OS, Latency, Distance, Active Ports
- Packet capture section with loading spinner overlay
- Capture results show total bytes and protocol tags with percentage tooltips
- Services list with state badges

**Spacing & Typography:**
- Consistent 4px-based spacing scale
- Larger touch targets (buttons, inputs, cards)
- Improved line heights and letter spacing
- Better visual hierarchy throughout

---

### ⚙️ Backend Improvements

**Configuration:**
- Environment variables: `API_HOST`, `API_PORT`, `CORS_ORIGINS`, `CAPTURE_INTERFACE`, `MAX_CAPTURES`
- Example: `CAPTURE_INTERFACE=eth0 MAX_CAPTURES=50 sudo ./run.sh`

**Performance:**
- WebSocket broadcast uses `asyncio.gather()` for concurrent clients
- Fire-and-forget progress updates (`asyncio.create_task`) to avoid scan blocking
- Automatic PCAP cleanup/rotation (keeps most recent 100 by default)

**Reliability:**
- Captures directory auto-created before mounting
- Proper exception handling in scanner chunks
- Connection pruning in WebSocket manager
- Removed duplicate variables and unreachable code

---

### 🐛 Bug Fixes

- Fixed duplicate `active_connections` variable in main.py
- Fixed unreachable `except` block in capturer.py
- Removed test code from scanner.py `__main__`
- Ensured captures directory exists before mounting StaticFiles
- Fixed WebSocket reconnect to properly reattach handlers
- Stabilized React callbacks with proper dependency arrays

---

## 📦 Installation

### Linux/macOS

```bash
# Clone and enter directory
git clone https://github.com/LEADRACER/NetVision.git
cd NetVision

# Install dependencies and run (requires root for nmap)
sudo ./run.sh
```

### Windows

```batch
# Clone repository, then:
run.bat
```
(Run as Administrator — right-click → "Run as administrator")

---

## 🔧 Manual Setup

**Backend (Python):**
```bash
cd backend
pip install -r requirements.txt
sudo python3 main.py  # or: python main.py (may limited nmap features)
```

**Frontend (Node.js):**
```bash
cd frontend
npm install
npm run dev
```

Access: http://localhost:5173

---

## 🎯 Quick Start Guide

1. **Start the application** (see installation above)
2. **Choose scan mode:**
   - Leave target empty → scans your local subnet
   - Enter custom CIDR → scans that network
   - Click **ALL SUBNETS** → scans 5 common private networks
3. **Optional: TRACE HOPS** — toggle ON to discover routers along path and scan their networks too
4. **Set duration** (optional): 30s or 1min for controlled scans
5. Click **EXECUTE SCAN**
6. Watch devices appear in real-time
7. Click any device card to see details, ports, and packet capture options

---

## 📋 Requirements

- **Python 3.8+** with pip
- **Node.js 18+** with npm
- **Nmap** (`sudo apt install nmap` or download from nmap.org)
- **Tshark** (Wireshark) for packet capture
- **Root/Administrator** privileges for full scanning capabilities

---

## 🏗️ Project Structure

```
NetVision/
├── backend/
│   ├── main.py           # FastAPI server & WebSocket endpoints
│   ├── scanner.py        # Nmap + scapy traceroute scanner
│   ├── capturer.py       # Tshark packet capture engine
│   ├── requirements.txt  # Python dependencies
│   └── captures/         # Saved PCAP files (auto-rotated)
├── frontend/
│   ├── src/
│   │   ├── App.jsx       # Main React component
│   │   ├── components/   # DeviceCard components
│   │   └── index.css     # Global styles
│   ├── index.html
│   ├── vite.config.js
│   └── package.json
├── run.sh                # Linux/macOS launcher
├── run.bat               # Windows launcher
└── README.md             # Original documentation
```

---

## 🔀 API Endpoints

- `GET /health` — Health check
- `GET /devices` — List discovered devices
- `GET /scan?target=...&profile=...&duration=...&trace_hops=...` — Start scan
- `POST /capture` — `{ ip, duration }` — Capture packets for IP
- `WS /ws` — Real-time updates (update, status, subnet_start events)
- `GET /captures/{filename}` — Download PCAP files

---

## 🧪 Testing

The application has been tested with:
- Local subnet discovery (192.168.1.0/24)
- Multi-subnet scanning (5 private ranges)
- 30-second and 1-minute duration scans
- Hop-based scanning to gateway (192.168.1.1)
- Packet capture and PCAP download

---

## 📈 Performance Notes

- **Caching:** OUI lookups cached in memory for fast vendor resolution
- **Chunking:** /24 subnets scanned in 16-IP chunks for responsive UI updates
- **Concurrency:** WebSocket broadcasts handle multiple clients efficiently
- **Memory:** PCAP rotation limits disk usage (default: keep 100 files)

---

## 🤝 Contributing

See original README.md for contribution guidelines.

---

## 📄 License

MIT License — Created by **LEADRACER**

---

## 🏷️ Version History

**v4.3.0** — Multi-Subnet & Hop-Based Scanning (this release)
- Added configurable scan durations (30s, 1min)
- Added all-private-subnets scan mode
- Added custom target CIDR input
- Added traceroute-based hop discovery and subnet scanning
- Added hop count display in UI
- Enhanced UI with sticky stats, progress bar, refresh button
- Improved device cards with port counts, OS previews
- Optimized spacing and typography throughout
- Fixed multiple backend bugs and memory leaks
- Added Windows support (run.bat)

**v4.2** — Original release with FastAPI backend, React frontend, WebSocket real-time updates, packet capture, and Neutral Zinc theme.

---

**🔗 GitHub Release:** https://github.com/LEADRACER/NetVision/releases/tag/v4.3.0
