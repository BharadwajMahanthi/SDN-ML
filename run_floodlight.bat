@echo off
REM ====================================================
REM  SDN-ML: Floodlight Controller Launcher
REM  Port: 6653 (OpenFlow)
REM  GUI:  http://localhost:8080/ui/index.html
REM ====================================================

echo [INFO] checking Java version...
java -version
if %errorlevel% neq 0 (
    echo [ERROR] Java is not installed or not in PATH!
    pause
    exit /b
)

echo.
echo [INFO] Starting Floodlight Controller...
echo [INFO] Listening on Port 6653 (OpenFlow) and 8080 (REST API)
echo.

cd floodlight_with_topoguard
java -jar target/floodlight.jar

pause
