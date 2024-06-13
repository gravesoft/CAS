@echo off
for %%# in (powershell.exe) do @if "%%~$PATH:#"=="" (
echo.
echo Windows PowerShell is not installed
pause
exit /b
)
set "_PSf=%~dp0Check-Activation-Status.ps1"
setlocal EnableDelayedExpansion
set "_PSf=!_PSf:'=''!"
powershell.exe -ExecutionPolicy Bypass -Command ^& "'!_PSf!'"
