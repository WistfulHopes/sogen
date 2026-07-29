for v in 0 1 2 3 5 6 7 8; do
  cmd.exe /c "taskkill /f /im analyzer.exe" >/dev/null 2>&1
  B="/mnt/c/dev/tokon/tools/sogen/_eac_$v.bat"
  printf '@echo off\r\nset "SteamAppId=4835540"\r\nset "SOGEN_CHILD_EMULATOR=1"\r\nset "SOGEN_DUMPER_SHIM=1"\r\nset "SOGEN_POKE_MAILBOX=6"\r\nset "SOGEN_EAC_UNK1_FIRST=%d"\r\ncd /d "C:\\dev\\tokon\\tools\\sogen\\build\\release\\artifacts"\r\nanalyzer.exe -v --backend whp -r registry --env SteamAppId 4835540 --env SteamGameId 4835540 --env EOS_USE_ANTICHEATCLIENTNULL 1 --env ALLUSERSPROFILE "C:\\ProgramData" --env ProgramData "C:\\ProgramData" "D:\\SteamLibrary\\steamapps\\common\\MTFSOpenBeta\\MTFS\\Binaries\\Win64\\MTFSSteamOpenBeta-Win64-Shipping.exe"\r\n' "$v" > "$B"
  cmd.exe /c "C:\\dev\\tokon\\tools\\sogen\\_eac_$v.bat" > "/mnt/c/dev/tokon/eac_$v.log" 2>&1
  L="/mnt/c/dev/tokon/eac_$v.log"
  echo "reply=$v lines=$(wc -l < $L) exit=$(grep -oP '(?<=exit_status=)0x\w+' $L | tail -1) eac=$(grep -c 'EAC\] ioctl' $L)"
done
