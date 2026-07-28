@echo off
REM No-pause variant so it can be driven non-interactively via UAC.
cd /d C:\dev\tokon\tools\sogen
echo [reg] start %DATE% %TIME% > C:\dev\tokon\grab_registry.log
call src\tools\grab-registry.bat "build\release\artifacts\registry" >> C:\dev\tokon\grab_registry.log 2>&1
echo [reg] exit %ERRORLEVEL% >> C:\dev\tokon\grab_registry.log
dir "build\release\artifacts\registry" >> C:\dev\tokon\grab_registry.log 2>&1
