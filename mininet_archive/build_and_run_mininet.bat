@echo off
REM ====================================================
REM  Run Mininet + Floodlight (Dockerized)
REM  Usage: Runs mininet-topoguard:latest
REM ====================================================

echo ============================================
echo Starting Container (Port 6633 Config)
echo ============================================

REM Clean up any old instance
docker rm -f mininet-topoguard >nul 2>&1

REM Run container
docker run -d --privileged ^
  --network host ^
  -v "%CD%":/workspace ^
  -w /workspace ^
  --name mininet-topoguard ^
  mininet-topoguard:latest ^
  /entrypoint.sh tail -f /dev/null

echo Container started.
echo Waiting for Floodlight...
timeout /t 10

echo.
echo ============================================
echo Ready!
echo ============================================
echo 1. Check Logs: docker logs -f mininet-topoguard
echo 2. Run Test:   docker exec mininet-topoguard python3 run_test_scenario.py
echo.
