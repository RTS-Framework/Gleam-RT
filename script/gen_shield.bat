@echo off

echo =======================================================================
echo Build Shield-Generator from https://github.com/RTS-Framework/GRT-Shield
echo =======================================================================
echo.

gen_shield.exe -arch 32 -out shield_x86.bin
gen_shield.exe -arch 64 -out shield_x64.bin

go run gen_shield.go
pause

del shield_x86.bin
del shield_x64.bin
