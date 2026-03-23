#!/bin/bash

# 🌐 NetVision: Real-Time Network Mapper Automated Setup & Runner

echo "=========================================================="
echo "🌐  NetVision: Real-Time Graphical Network Mapper"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run this script as root (sudo ./run.sh)."
  exit 1
fi

echo "[*] 1. Installing Backend Dependencies..."
pip3 install -r backend/requirements.txt -q --break-system-packages 2>/dev/null || pip3 install -r backend/requirements.txt -q

echo "[*] 2. Ensuring Frontend Dependencies..."
cd frontend && npm install --silent && cd ..

# Background tasks for servers
echo "[*] 3. Launching NetVision Servers..."

# Start Backend
python3 backend/main.py > /dev/null 2>&1 &
BACKEND_PID=$!

# Start Frontend
cd frontend && npm run dev > /dev/null 2>&1 &
FRONTEND_PID=$!
cd ..

echo "----------------------------------------------------------"
echo "[✓] NetVision is now LIVE!"
echo "[*] Backend  : http://localhost:8000"
echo "[*] Frontend : http://localhost:5173"
echo "----------------------------------------------------------"
echo "[!] Press [CTRL+C] to stop the servers."

# Trap to kill background processes on exit
trap "kill $BACKEND_PID $FRONTEND_PID; exit" INT TERM

# Wait for user to manually exit
wait
