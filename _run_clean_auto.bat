@echo off
rem Canonical MTFS run. Only what is required -- no behaviour-changing diagnostics.
rem   SOGEN_TF_DEBUG is required, not optional: without the hooks it installs the run
rem   regresses into an unbounded exception-unwind loop (a WHP translation-block heisenbug).
rem   SOGEN_SWALLOW_DB is deliberately NOT set -- it suppresses single-steps Theia relies on.
set "SteamAppId=4835540"
set "SOGEN_CHILD_EMULATOR=1"
set "SOGEN_DUMPER_SHIM=1"
set "SOGEN_TF_DEBUG=1"
set "SOGEN_POKE_MAILBOX=6"
cd /d "C:\dev\tokon\tools\sogen\build\release\artifacts"
analyzer.exe -v --backend whp -r registry --env SteamAppId 4835540 --env SteamGameId 4835540 --env EOS_USE_ANTICHEATCLIENTNULL 1 --env ALLUSERSPROFILE "C:\ProgramData" --env ProgramData "C:\ProgramData" "D:\SteamLibrary\steamapps\common\MTFSOpenBeta\MTFS\Binaries\Win64\MTFSSteamOpenBeta-Win64-Shipping.exe"
