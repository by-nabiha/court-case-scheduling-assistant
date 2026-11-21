@echo off
REM One-click start for Windows
cd /d "%~dp0"
if not exist .venv (
  python -m venv .venv
)
call .venv\Scripts\activate
pip install -q -r requirements.txt
if not exist instance\court.db (
  python seed.py --reset
)
echo.
echo Open http://127.0.0.1:5000  in your browser   (password for all demo users: Court@2026!)
python app.py
