@echo off
taskkill /F /IM node.exe /FI "WINDOWTITLE eq TSW Desktop*" >nul 2>&1
echo If TSW is still running, close the server window.
pause
