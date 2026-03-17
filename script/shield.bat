@echo off

echo =======================================================================
echo Build Shield-Generator from https://github.com/RTS-Framework/GRT-Shield
echo =======================================================================
echo.

shield.exe -arch 32 -mod -out ../asm/inst/shield_x86.inst
shield.exe -arch 64 -mod -out ../asm/inst/shield_x64.inst
pause
