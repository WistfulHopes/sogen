@echo off
REM Theia's parent parks forever; the CHILD process is the real game. Run
REM runtime.dll directly as the main image with the environment the parent would
REM have supplied (--env PACKER_CHILD 1 makes sogen mint a section and inject
REM PACKER_SECTION / PACKER_FUNCTIONALITY).
set "SteamAppId=4835540"
cd /d "C:\dev\tokon\tools\sogen\build\release\artifacts"
analyzer.exe -v --backend whp --reproducible -r registry --env PACKER_CHILD 1 --env SteamAppId 4835540 --env SteamGameId 4835540 --env EOS_USE_ANTICHEATCLIENTNULL 1 "D:\SteamLibrary\steamapps\common\MTFSOpenBeta\MTFS\Binaries\Win64\runtime.dll"
