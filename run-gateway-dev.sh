#!/bin/bash

# aw-aiguard Gateway Dev Runner
# This script activates the virtual environment and starts the local proxy server.

# Get the directory where the script is located
PROJECT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$PROJECT_ROOT"

echo "🚀 Starting aw-aiguard Local Gateway Proxy..."

# 1. Activate the virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    echo "❌ Error: Virtual environment not found at venv/bin/activate"
    exit 1
fi

# 2. Set Python path so the 'gateway' package is discoverable
export PYTHONPATH=$PYTHONPATH:.

# 3. Run the server
# We use the app from gateway.main and listen on port 9020
uvicorn gateway.main:app --port 9020 --reload
