# Loaders

Compact Windows loaders for executing patched/scrambled shellcode. Both avoid spawning a console host and resolve APIs at runtime.

- `simple_loader-winmain.c`  
  GUI-subsystem entry (WinMain). Walks NTDLL exports for heap APIs, allocates RX heap, copies packed shellcode from the generated header, runs the polymorphic seed-based decode (XOR/scramble), RLE-decodes, then executes. Stays quiet on launch with only minimal CRT imports.

- `simple_loader-minified.c`  
  Footprint-first build with no CRT and no static imports. Compiled with `/NODEFAULTLIB`, merged sections, and tight alignment. Reuses the same polymorphic decode + RLE path, resolving needed procedures dynamically for a smaller, quieter dropper.

## Building

From a Visual Studio Developer Command Prompt:

```
build_scripts\build-winmain.bat
build_scripts\build-minified.bat
```

Artifacts are written to `build_artifacts\`. Ensure `shellcode.h` (generated from your patched shellcode) is present in the repo root before building.
