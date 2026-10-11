@echo off
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\pythonw.exe" (
    start "" ".venv\Scripts\pythonw.exe" "desktop.py"
    exit /b 0
)

where pyw >nul 2>nul
if %errorlevel% equ 0 (
    start "" pyw -3.10 "desktop.py"
    exit /b 0
)

where pythonw >nul 2>nul
if %errorlevel% equ 0 (
    start "" pythonw "desktop.py"
    exit /b 0
)

echo Python 3.10 or newer was not found.
echo Install Python, then run:  python -m pip install -r requirements.txt
pause
exit /b 1
