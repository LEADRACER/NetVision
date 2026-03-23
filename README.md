# 🛰️ NetVision

**Real-time Network Intelligence & Discovery Dashboard**

NetVision is a high-performance, industrial-grade network mapping tool designed for instant visibility and security awareness. Built with a **FastAPI** backend and a **React** frontend, it provides a seamless, ultra-lightweight experience for discovering devices, services, and vulnerabilities on your local network.

![NetVision Banner](https://img.shields.io/badge/Version-4.2-blue?style=for-the-badge)
![Tech Stack](https://img.shields.io/badge/Stack-FastAPI%20|%20React-green?style=for-the-badge)

---

## ✨ Key Features

- 🕵️ **Progressive Discovery**: Real-time updates as nodes are found (no waiting for the full scan).
- 🛠️ **Scan Profiles**:
  - **Quick**: Fast sweep for active hosts.
  - **Deep**: Intensive OS fingerprinting and service detection.
  - **Security**: Advanced vulnerability scanning using Nmap scripts.
- 🎨 **Industrial UI (v4.2)**:
  - **Neutral Grey Palette**: Professional Zinc-based theme (low contrast, zero blue-tint).
  - **Technical Dotted Grid**: Blueprint-style background for better spatial awareness.
  - **Green/Red Status**: Instant visual cues for healthy vs. vulnerable nodes.
- ⚡ **Ultra-Lightweight**: Zero-animation grid architecture for maximum compatibility and speed.
- 📡 **Live WebSockets**: Direct, low-latency data stream from the scanning engine.

---

## 🚀 Getting Started

### Prerequisites

- **Nmap**: Required for the scanning engine (`sudo apt install nmap`).
- **Python 3.8+**
- **Node.js 18+**

### Backend Setup

1. Navigate to the `backend` directory.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the server (Root/Sudo required for Nmap):
   ```bash
   sudo python3 main.py
   ```

### Frontend Setup

1. Navigate to the `frontend` directory.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the development server:
   ```bash
   npm run dev -- --host
   ```

---

## 🛠️ Technology Stack

- **Backend**: Python, FastAPI, Uvicorn, Python-Nmap.
- **Frontend**: React, Vite, Lucide React, Framer Motion (Optimized).
- **Communication**: WebSockets (Real-time), REST API (Commands).

---

## 🛡️ Security Note

NetVision requires elevated privileges (root/sudo) to perform advanced Nmap operations like OS detection and vulnerability scanning. Use responsibly on networks you own or have permission to test.

---

## 📜 License

Created by **LEADRACER**. Licensed under the MIT License.
