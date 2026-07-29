@echo off
set "SteamAppId=4835540"
set "SOGEN_CHILD_EMULATOR=1"
set "SOGEN_DUMPER_SHIM=1"
set "SOGEN_TF_DEBUG=1"
set "SOGEN_C0210_BP=1"
cd /d "C:\dev\tokon\tools\sogen\build\release\artifacts"
analyzer.exe -v --backend whp -r registry --env SteamAppId 4835540 --env SteamGameId 4835540 --env EOS_USE_ANTICHEATCLIENTNULL 1 "D:\SteamLibrary\steamapps\common\MTFSOpenBeta\MTFS\Binaries\Win64\MTFSSteamOpenBeta-Win64-Shipping.exe"
