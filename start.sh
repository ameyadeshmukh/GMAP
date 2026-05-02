#!/bin/bash
# GMAP startup script — run from the GMAP root directory

echo "Starting Docker services..."
docker compose up -d
echo "Docker services started."

# Cross-platform venv activation
if [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
else
    source venv/bin/activate
fi

echo "Starting services (Ctrl+C to stop all)..."

PYTHONPATH=backend celery -A backend.celery_app worker --pool=solo --loglevel=info &
CELERY_PID=$!

uvicorn backend.api:app --reload &
FASTAPI_PID=$!

(cd frontend && streamlit run app.py) &
STREAMLIT_PID=$!

echo ""
echo "All services running:"
echo "  FastAPI   → http://127.0.0.1:8000"
echo "  Streamlit → http://localhost:8501"
echo "  Redis UI  → http://localhost:8081"
echo "  pgAdmin   → http://localhost:5050"
echo ""

trap 'echo "Stopping services..."; kill $CELERY_PID $FASTAPI_PID $STREAMLIT_PID 2>/dev/null; exit' INT TERM

wait