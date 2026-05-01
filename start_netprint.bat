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

for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":5000" ^| findstr "LISTENING"') do (
  taskkill /PID %%P /F >nul 2>nul
)

start "" cmd /c "timeout /t 3 >nul && start http://127.0.0.1:5000"
%PY_CMD% -c "import app; app.app.run(debug=False, host='0.0.0.0', port=5000)"

echo.
echo Server stopped.
pause

endlocal
