#!/bin/bash
# ReconForge 1-Click Desktop Launcher for Linux / macOS / WSL

echo "==================================================="
echo "Starting ReconForge Local App..."
echo "==================================================="

# Check dependencies
if [ ! -d "node_modules" ]; then
    echo "Installing npm dependencies..."
    npm install
fi

# Start the background server
node server.js &
SERVER_PID=$!

sleep 2

# Open in application window mode (no URL bar)
if command -v google-chrome >/dev/null 2>&1; then
    google-chrome --app=http://localhost:3000
elif command -v chromium >/dev/null 2>&1; then
    chromium --app=http://localhost:3000
elif command -v brave-browser >/dev/null 2>&1; then
    brave-browser --app=http://localhost:3000
elif [[ "$OSTYPE" == "darwin"* ]]; then
    open -a "Google Chrome" --args --app=http://localhost:3000 || open http://localhost:3000
elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open http://localhost:3000
else
    echo "ReconForge is running at http://localhost:3000"
fi

wait $SERVER_PID
