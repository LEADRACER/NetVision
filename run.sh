#!/bin/bash

# 🌐 NetVision: Real-Time Network Mapper Automated Setup & Runner

echo "=========================================================="
echo "🌐  NetVision: Real-Time Graphical Network Mapper"
echo "=========================================================="

# Configuration via environment variables
export API_HOST="${API_HOST:-0.0.0.0}"
export API_PORT="${API_PORT:-8000}"
export CORS_ORIGINS="${CORS_ORIGINS:-*}"
export CAPTURE_INTERFACE="${CAPTURE_INTERFACE:-wlan0}"
export MAX_CAPTURES="${MAX_CAPTURES:-100}"

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run this script as root (sudo ./run.sh)."
  echo "[*] Note: Nmap OS detection and packet capture require elevated privileges."
  exit 1
fi

echo "[*] 1. Installing Backend Dependencies..."
pip3 install -r backend/requirements.txt -q --break-system-packages 2>/dev/null || pip3 install -r backend/requirements.txt -q

echo "[*] 2. Ensuring Frontend Dependencies..."
cd frontend && npm install --silent && cd ..

# Background tasks for servers
echo "[*] 3. Launching NetVision Servers..."

# Start Backend
echo "[*]   Backend  : http://$API_HOST:$API_PORT"
python3 backend/main.py > /tmp/netvision-backend.log 2>&1 &
BACKEND_PID=$!
sleep 2

# Verify backend started
if ! ps -p $BACKEND_PID > /dev/null; then
    echo "[!] Backend failed to start. Check /tmp/netvision-backend.log"
    exit 1
fi

# Start Frontend
echo "[*]   Frontend : http://localhost:5173"
cd frontend && npm run dev > /tmp/netvision-frontend.log 2>&1 &
FRONTEND_PID=$!
cd ..
sleep 2

# Verify frontend started
if ! ps -p $FRONTEND_PID > /dev/null; then
    echo "[!] Frontend failed to start. Check /tmp/netvision-frontend.log"
    kill $BACKEND_PID
    exit 1
fi

echo "----------------------------------------------------------"
echo "[✓] NetVision is now LIVE!"
echo "[*] Backend  : http://$API_HOST:$API_PORT"
echo "[*] Frontend : http://localhost:5173"
echo "[*] API URL  : http://localhost:$API_PORT"
echo "----------------------------------------------------------"
echo "[!] Press [CTRL+C] to stop the servers."
echo "[*] Logs:"
echo "    Backend  → /tmp/netvision-backend.log"
echo "    Frontend → /tmp/netvision-frontend.log"
echo "----------------------------------------------------------"

# Trap to kill background processes on exit
trap "kill $BACKEND_PID $FRONTEND_PID; exit" INT TERM

# Wait for user to manually exit
wait
