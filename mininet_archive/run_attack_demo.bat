@echo off
REM Quick Demo Launcher for SDN Attack Demonstration

echo ============================================
echo SDN Attack Demonstration with TopoGuard
echo ============================================
echo.

echo This demo will:
echo 1. Verify Floodlight is running
echo 2. Launch Mininet with custom topology
echo 3. Run attack scenarios
echo 4. Collect data for ML analysis
echo.

REM Check Floodlight
echo [Step 1] Checking Floodlight status...
curl -s http://localhost:8080/wm/core/controller/summary/json >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Floodlight is not running or not accessible!
    echo.
    echo Please start Floodlight first:
    echo   cd floodlight_with_topoguard
    echo   java -jar target\floodlight.jar
    echo.
    pause
    exit /b 1
)
echo [OK] Floodlight is running

echo.
echo [Step 2] Starting Mininet network...
echo Note: This will run in Docker
echo.

docker run -it --rm --privileged ^
  --name mini net-demo ^
  -v %CD%:/workspace ^
  mininet-custom ^
  mn --custom /workspace/se.py --topo mytopo ^
  --controller=remote,ip=192.168.1.16,port=6653

echo.
echo Demo completed!
pause
