@echo off
setlocal
cd /d "%~dp0"
if not exist node.exe (
  echo First launch: downloading the portable Node.js runtime...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $zip=Join-Path $env:TEMP 'tsw-node.zip'; Invoke-WebRequest 'https://nodejs.org/dist/v22.16.0/node-v22.16.0-win-x64.zip' -OutFile $zip; Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $env:TEMP 'tsw-node') -Force; Copy-Item (Join-Path $env:TEMP 'tsw-node\node-v22.16.0-win-x64\node.exe') '.\node.exe' -Force; Remove-Item $zip -Force"
  if errorlevel 1 (
    echo Could not download portable Node.js. Check your internet connection and try again.
    pause
    exit /b 1
  )
)
start "" http://127.0.0.1:4173
node.exe server.mjs
pause
