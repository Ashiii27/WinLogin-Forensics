@echo off
REM Launch the WinLogin Forensics Streamlit UI
cd /d "%~dp0"
if exist venv\Scripts\activate.bat call venv\Scripts\activate.bat
streamlit run src\app.py --server.address 0.0.0.0
