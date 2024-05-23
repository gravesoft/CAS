@echo off
set "_PSf=%~dp0Check-Activation-Status.ps1"
setlocal EnableDelayedExpansion
set "_PSf=!_PSf:'=''!"
powershell.exe -ExecutionPolicy Bypass -Command ^& "'!_PSf!'"
