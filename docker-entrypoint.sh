#!/bin/bash
set -e

# Project Unit42-FirmwareX Docker Entrypoint
# Palo Alto Networks // Unit 42

case "$1" in
  api)
    echo "Starting Unit42-FirmwareX REST API on port 8000..."
    exec python -m uvicorn firmwarex.api.app:app --host 0.0.0.0 --port 8000
    ;;
  dashboard)
    echo "Starting Unit42-FirmwareX Streamlit Dashboard on port 8501..."
    exec streamlit run firmwarex/dashboard/app.py --server.port 8501 --server.address 0.0.0.0 --server.headless true
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
    echo "Starting both REST API (8000) and Streamlit Dashboard (8501)..."
    python -m uvicorn firmwarex.api.app:app --host 0.0.0.0 --port 8000 &
    exec streamlit run firmwarex/dashboard/app.py --server.port 8501 --server.address 0.0.0.0 --server.headless true
    ;;
  *)
    exec "$@"
    ;;
esac
