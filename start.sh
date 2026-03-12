#!/bin/bash
echo "🚀 Starting AION-X..."

# Start backend in background
cd /home/kakashi/AION-X
export PYTHONPATH="${PYTHONPATH}:/home/kakashi/AION-X"
uvicorn backend.main:app --reload --port 8000 &
BACKEND_PID=$!

# Start frontend
cd frontend
python3 -m http.server 3000 &
FRONTEND_PID=$!

echo "✅ Backend running on http://localhost:8000 (PID: $BACKEND_PID)"
echo "✅ Frontend running on http://localhost:3000 (PID: $FRONTEND_PID)"
echo "📝 Press Ctrl+C to stop both"

# Wait for Ctrl+C
trap "kill $BACKEND_PID $FRONTEND_PID; exit" INT
wait
