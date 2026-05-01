@echo off
setlocal

cd /d "%~dp0"

echo Starting NetPrint server...
echo.

set "PY_CMD="
where py >nul 2>nul && set "PY_CMD=py -3"
if not defined PY_CMD (
  where python >nul 2>nul && set "PY_CMD=python"
)

if not defined PY_CMD (
  echo ERROR: Python was not found on PATH.
  echo Install Python and try again.
  pause
  exit /b 1
)

start "" cmd /c "timeout /t 3 >nul && start http://127.0.0.1:5000"
%PY_CMD% app.py

echo.
echo Server stopped.
pause

endlocal
