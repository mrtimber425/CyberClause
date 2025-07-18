#!/bin/bash
echo "🛡️ Launching CyberClause GUI Launcher..."
cd "$(dirname "$0")"

# Check if venv exists at the root
if [ ! -d "venv" ]; then
    echo "🔧 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate venv
source venv/bin/activate

# Install requirements
echo "📦 Installing dependencies..."
pip install --upgrade pip > /dev/null
pip install -r requirements.txt

# Run launcher from core/
echo "🚀 Starting core/launcher.py..."
python launcher.py
