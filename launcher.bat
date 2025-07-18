@echo off
echo 🛡️ Launching Application with Tkinter GUI...
cd /d "%~dp0"

REM Check if venv exists
if not exist "venv\" (
    echo 🔧 Creating virtual environment...
    python -m venv venv
)

REM Install requirements
echo 📦 Installing dependencies...
call venv\Scripts\activate
pip install --upgrade pip >nul
pip install -r requirements.txt

REM Launch the GUI launcher
echo 🚀 Starting launcher.py...
python launcher.py

pause
