#!/usr/bin/env bash
# One-command start for macOS / Linux
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt
[ -f instance/court.db ] || python seed.py --reset
echo "Open http://127.0.0.1:5000  (password for all demo users: Court@2026!)"
python app.py
