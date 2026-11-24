@echo off
setlocal
title Build Defender PC Guard
cd /d "%~dp0"

echo ==========================================
echo   Building Defender PC Guard (one-file exe)
echo ==========================================
echo.

where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python was not found on PATH.
    echo Install Python 3 and make sure "python" works in a terminal.
    echo.
    pause
    exit /b 1
)

python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: PyInstaller is not installed for this Python.
    echo Install it with:  python -m pip install pyinstaller
    echo.
    pause
    exit /b 1
)

echo Running PyInstaller...
echo.
python -m PyInstaller --noconfirm --clean DefenderPCGuard.spec
if errorlevel 1 goto :failed

if not exist "dist\DefenderPCGuard.exe" (
    echo.
    echo ERROR: PyInstaller finished but dist\DefenderPCGuard.exe is missing.
    echo.
    pause
    exit /b 1
)

echo.
echo Copying the new build into this folder...
copy /y "dist\DefenderPCGuard.exe" "DefenderPCGuard.exe" >nul
if errorlevel 1 goto :copy_failed

echo.
echo Build complete:
echo   %CD%\DefenderPCGuard.exe
echo.
echo Copying it to wherever you actually run it is up to you.
echo.
pause
exit /b 0

:copy_failed
echo.
echo ERROR: Could not replace DefenderPCGuard.exe in this folder.
echo Close Defender PC Guard if it is running, then run this script again.
echo The new build is still available in dist\
echo.
pause
exit /b 1

:failed
echo.
echo BUILD FAILED - see the PyInstaller messages above.
echo.
pause
exit /b 1
