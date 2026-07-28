@echo off
cd /d "C:\dev\tokon\tools\sogen\build\release\artifacts"
analyzer.exe -v --backend whp --reproducible -r registry --env PACKER_CHILD 20000 --env SteamAppId 4835540 --env EOS_USE_ANTICHEATCLIENTNULL 1 "D:\SteamLibrary\steamapps\common\MTFSOpenBeta\MTFS\Binaries\Win64\runtime.dll"
