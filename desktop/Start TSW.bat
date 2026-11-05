@echo off
cd /d "%~dp0"
if not exist node.exe (
  echo Portable Node.js runtime missing. Download the desktop ZIP from the GitHub Actions build.
  pause
  exit /b 1
)
start "" http://127.0.0.1:4173
node.exe server.mjs
pause
