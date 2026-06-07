# Flip Config Bypass

Small Windows tray utility that watches a user whitelist and injects a tiny x64 payload into matching processes. The payload hides `NvAPI_D3D12_SetFlipConfig` by returning `nullptr` when the game asks `nvapi_QueryInterface` for interface ID `0xF3148C42`.

This replaces the older `dxgi.dll` proxy approach. There is no fake DXGI DLL to copy next to a game executable.

## Build

The project is intended to build directly on GitHub Actions. Open the repo's **Actions** tab, run **Build**, then download the `FlipConfigBypass-x64` artifact.

The artifact contains:

```text
FlipConfigBypass.exe
FlipConfigPayload.dll
```

Keep both files in the same folder.

## Use

Run `FlipConfigBypass.exe`. It creates these files beside the EXE if they do not already exist:

```text
whitelist.txt
FlipConfigBypass.log
```

Right-click the tray icon to:

- edit the whitelist
- view the log
- pause watching
- toggle Start with Windows
- exit

Whitelist entries can be either executable names or full paths:

```text
GTA5.exe
C:\Games\Cyberpunk 2077\bin\x64\Cyberpunk2077.exe
```

The log only records meaningful events, such as successful injections and failures like access denied or architecture mismatch.

## Notes

- x64 targets only
- no overlay
- no settings UI beyond the whitelist editor
- no NVIDIA SDK dependency
- no external hook library
- no attempt to bypass anti-cheat or protected process restrictions

Some games, especially multiplayer games with anti-cheat, may block injection or treat it as unsupported.
