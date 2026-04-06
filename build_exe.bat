@echo off
setlocal

REM Build a Windows .exe from the Tkinter frontend.
REM Requirements:
REM   pip install pyinstaller pyclamd
REM   Install ClamAV and ensure clamd or clamscan is available.

pyinstaller --noconfirm --clean --onefile --windowed --name AntivirusScanner antivirus_scanner_gui.py

echo.
echo Build complete. EXE should be in the dist folder:
echo   dist\AntivirusScanner.exe
