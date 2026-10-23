#!/bin/bash
set -e

# Project Unit42-FirmwareX Docker Entrypoint
# Palo Alto Networks // Unit 42

# Handle dynamic PORT from Render, Railway, Heroku, or standard Docker environments
PORT="${PORT:-8501}"
COMMAND="${1:-dashboard}"

case "$COMMAND" in
  dashboard)
    echo "Starting Unit42-FirmwareX Streamlit Dashboard on port $PORT..."
    exec streamlit run firmwarex/dashboard/app.py \
      --server.port "$PORT" \
      --server.address 0.0.0.0 \
      --server.headless true \
      --server.enableCORS false \
      --server.enableXsrfProtection false
    ;;
  api)
    echo "Starting Unit42-FirmwareX REST API on port $PORT..."
    exec python -m uvicorn firmwarex.api.app:app --host 0.0.0.0 --port "$PORT"
    ;;
  test)
    echo "Executing Unit42-FirmwareX test suite..."
    exec pytest -v --cov=firmwarex --cov-report=term
    ;;
  analyze)
    shift
    echo "Running CLI analysis on firmware: $@"
    exec python scripts/run_sample_analysis.py "$@"
    ;;
  all)
    echo "Starting REST API on port 8000 and Streamlit Dashboard on port $PORT..."
    python -m uvicorn firmwarex.api.app:app --host 0.0.0.0 --port 8000 &
    exec streamlit run firmwarex/dashboard/app.py \
      --server.port "$PORT" \
      --server.address 0.0.0.0 \
      --server.headless true \
      --server.enableCORS false \
      --server.enableXsrfProtection false
    ;;
  *)
    exec "$@"
    ;;
esac
