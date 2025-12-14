@echo off
setlocal

rem Ensure the Visual Studio build tools environment is loaded (run from a Developer Command Prompt).
where cl >nul 2>&1
if errorlevel 1 (
    echo [build] cl.exe not found. Please run this from a "x64 Native Tools Command Prompt for VS".
    exit /b 1
)

set SRC=simple_loader.c
set OUT=simple_loader.exe
set DEFINES=/D shellcode=patched_bin /D shellcode_len=patched_bin_len

echo [build] Compiling %SRC% -> %OUT%
cl /nologo /Os /GS- /GR- /W3 /Zl /Gy %DEFINES% /Fe:%OUT% %SRC% ^
  /link /NODEFAULTLIB:libcmt /ENTRY:MyEntry /SUBSYSTEM:CONSOLE ^
  /OPT:REF /OPT:ICF /INCREMENTAL:NO /MERGE:.rdata=.text /MERGE:.pdata=.text /ALIGN:16 /IGNORE:4108 ^
  kernel32.lib
if errorlevel 1 exit /b 1

echo [build] Done.
exit /b 0
