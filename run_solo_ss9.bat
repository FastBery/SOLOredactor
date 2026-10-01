@echo off
setlocal
cd /d "%~dp0"
python "%~dp0solo_ss9_tool_local.py" %*
if errorlevel 1 (
    echo.
    echo [ERROR] Command failed.
)
echo.
pause
