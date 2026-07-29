@echo off
taskkill /F /IM cl.exe >nul 2>&1
taskkill /F /IM ninja.exe >nul 2>&1
taskkill /F /IM cmake.exe >nul 2>&1
taskkill /F /IM link.exe >nul 2>&1
echo done
