@echo off
REM Right-click this file -> "Run as administrator".
REM Opens an inbound firewall hole for sogen's GDB stub (TCP 28960) so WSL can reach it
REM across the WSL2 virtual network boundary. Only allows that one port.
netsh advfirewall firewall add rule name="Sogen GDB stub" dir=in action=allow protocol=TCP localport=28960
pause
