@echo off
set "SteamAppId=4835540"
set "SOGEN_TRACE_SHARED_SECTION=1"
cd /d "C:\dev\tokon\tools\sogen\build\release\artifacts"
analyzer.exe -v --backend whp --reproducible -r registry --env SteamAppId 4835540 --env SteamGameId 4835540 --env EOS_USE_ANTICHEATCLIENTNULL 1 "D:\SteamLibrary\steamapps\common\MTFSOpenBeta\MTFS\Binaries\Win64\MTFSSteamOpenBeta-Win64-Shipping.exe"
