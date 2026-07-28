@echo off
REM runtime.dll is an EXE (IMAGE_FILE_DLL clear, subsystem GUI, entry 0x8AD880).
REM Theia spawns it as a CHILD process during init; sogen has no child support, so
REM try emulating that child directly as the main image.
set "SteamAppId=4835540"
cd /d "C:\dev\tokon\tools\sogen\build\release\artifacts"
analyzer.exe -v --backend whp --reproducible -r registry --env SteamAppId 4835540 --env SteamGameId 4835540 --env EOS_USE_ANTICHEATCLIENTNULL 1 "D:\SteamLibrary\steamapps\common\MTFSOpenBeta\MTFS\Binaries\Win64\runtime.dll"
