@echo off
REM Right-click this file -> "Run as administrator".
REM Wraps src\tools\grab-registry.bat, pointing the output at the artifacts folder
REM analyzer.exe will read from (build\release\artifacts\registry).
cd /d "%~dp0"
call src\tools\grab-registry.bat "build\release\artifacts\registry"
pause
