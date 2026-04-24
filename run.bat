:: 🌐 NetVision: Real-Time Network Mapper Automated Setup & Runner for Windows
:: Requires: Python 3.8+, Node.js 18+, Nmap, Tshark (Wireshark)

@echo off
echo ==========================================================
echo 🌐  NetVision: Real-Time Graphical Network Mapper
echo ==========================================================

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Please run this script as Administrator (right-click -> Run as administrator)
    pause
    exit /b 1
)

echo [*] 1. Installing Backend Dependencies...
pip install -r backend\requirements.txt -q

echo [*] 2. Ensuring Frontend Dependencies...
cd frontend && npm install --silent && cd ..

echo [*] 3. Launching NetVision Servers...

:: Start Backend
echo [*]   Backend  : http://localhost:8000
python backend\main.py > NUL 2>&1 &
set BACKEND_PID=!

:: Start Frontend
cd frontend && npm run dev > NUL 2>&1 &
set FRONTEND_PID=!
cd ..

echo -----------------------------------------------------------
echo [✓] NetVision is now LIVE!
echo [*] Backend  : http://localhost:8000
echo [*] Frontend : http://localhost:5173
echo -----------------------------------------------------------
echo [!] Press [CTRL+C] to stop the servers.

:: Trap to kill background processes on exit
taskkill /PID %BACKEND_PID% /F >NUL 2>&1
taskkill /PID %FRONTEND_PID% /F >NUL 2>&1
