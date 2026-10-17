@echo off
title Defender PC Guard
cd /d "%~dp0"
python DefenderPCGuard.pyw
if errorlevel 1 (
  echo.
  echo Could not start. Make sure Python 3 is installed and on your PATH.
  pause
)
