@echo off
REM Quick start script for Mininet Docker on Windows

echo ============================================
echo Mininet Docker Quick Start
echo ============================================
echo.

REM Check if Docker is running
docker ps >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Desktop is not running!
    echo.
    echo Please start Docker Desktop and try again.
    echo.
    pause
    exit /b 1
)

echo [OK] Docker is running
echo.

REM Pull Mininet image
echo Pulling Mininet Docker image...
docker pull iwaseyusuke/mininet

echo.
echo ============================================
echo Starting Mininet with Floodlight controller
echo ============================================
echo.
echo Controller: localhost:6653
echo Topology: Tree (depth=2, fanout=2)
echo.
echo Press Ctrl+C to stop
echo.

REM Run Mininet
docker run -it --rm --privileged --name mininet --network host iwaseyusuke/mininet mn--controller=remote,ip=host.docker.internal,port=6653 --topo tree,depth=2,fanout=2

echo.
echo Mininet stopped.
pause
