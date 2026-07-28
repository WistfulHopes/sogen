@echo off
tasklist | findstr /i "ninja cl.exe cmake link.exe MSBuild"
