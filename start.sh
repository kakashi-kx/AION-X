#!/bin/bash
echo "🚀 Starting AION-X..."

# Kill any existing processes
pkill -f uvicorn
pkill -f cors-frontend.py
sleep 2

# Start backend
cd /home/kakashi/AION-X
export PYTHONPATH="${PYTHONPATH}:/home/kakashi/AION-X"
uvicorn backend.main:app --reload --port 8000 --host 0.0.0.0 &
BACKEND_PID=$!
echo "✅ Backend running on http://localhost:8000 (PID: $BACKEND_PID)"

# Wait a moment for backend to start
sleep 3

# Start frontend with CORS proxy
python3 cors-frontend.py &
FRONTEND_PID=$!
echo "✅ Frontend running on http://localhost:3000 (PID: $FRONTEND_PID)"
echo "📝 Press Ctrl+C to stop both"

# Function to kill processes on exit
cleanup() {
    echo -e "\n👋 Shutting down AION-X..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    wait $BACKEND_PID $FRONTEND_PID 2>/dev/null
    echo "✅ Shutdown complete"
    exit
}

# Trap Ctrl+C
trap cleanup INT

# Wait
wait
