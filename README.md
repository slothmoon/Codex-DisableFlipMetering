# Flip Config Bypass

## About

Flip Config Bypass is a small Windows tray utility for disabling NVIDIA flip metering in whitelisted x64 applications.

It watches a user-managed whitelist, injects a tiny x64 payload DLL into matching processes, and makes one NVAPI interface unavailable:

```text
0xF3148C42 - NvAPI_D3D12_SetFlipConfig
```

The payload hooks `nvapi64.dll!nvapi_QueryInterface`. When a program asks for that one interface ID, the hook returns `nullptr`. Other NVAPI interface queries are forwarded to the real `nvapi_QueryInterface`.

The tool is intentionally narrow:

- no `dxgi.dll` proxy
- no overlay
- no game file replacement
- no NVIDIA SDK dependency
- no external hook library
- no 32-bit payload path
- no anti-cheat or protected-process bypass

## Download

Builds are produced by GitHub Actions.

Open the repo's **Actions** tab, run **Build**, then download the `FlipConfigBypass-x64` artifact.

The artifact contains:

```text
FlipConfigBypass.exe
FlipConfigPayload.dll
```

Keep both files in the same folder.

## Usage

Run `FlipConfigBypass.exe`. The app sits in the system tray and creates these files beside the EXE if needed:

```text
whitelist.txt
FlipConfigBypass.log
```

Only one tray instance can run at a time.

Right-click the tray icon to:

- edit the whitelist
- open the log with your default `.log` file handler
- pause watching
- toggle Start with Windows
- exit

Whitelist entries can be executable names or full paths:

```text
GTA5.exe
C:\Games\Cyberpunk 2077\bin\x64\Cyberpunk2077.exe
```

Filename entries are usually easiest. Full-path entries are supported when you want to target one exact install location.

## Logging

The log records meaningful events only, such as:

```text
[14:32:01] GTA5.exe (PID 9432) - injected OK
[14:42:55] ProtectedGame.exe (PID 2216) - failed, access denied
```

Non-whitelisted processes are not logged.

At startup, the app clears `FlipConfigBypass.log` if it is larger than `2 MB`, keeping the file small without background log rotation.

## Start With Windows

`Start with Windows` uses the current user's registry Run key:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

It does not install a service and should not require administrator permission.

If you move the app folder, toggle Start with Windows off and on again so Windows points to the new EXE path.

## How It Works

The tray app scans running processes every few seconds. If a process matches the whitelist, the app verifies that it is x64, then loads `FlipConfigPayload.dll` into that process.

Inside the target process, the payload:

- patches direct imports of `nvapi64.dll!nvapi_QueryInterface`
- patches `GetProcAddress` imports so dynamic NVAPI lookups receive the hook
- blocks only interface ID `0xF3148C42`
- scans newly loaded modules for a limited startup window, then stops

The tray app still detects 32-bit targets and logs an architecture mismatch instead of trying to inject the x64 payload.

## False Positives

This tool uses normal user-mode DLL injection into whitelisted processes. Antivirus products may flag that behavior even though the source is small and auditable.

If you use it personally, prefer a narrow exclusion for the folder containing:

```text
FlipConfigBypass.exe
FlipConfigPayload.dll
whitelist.txt
FlipConfigBypass.log
```

Do not allow a broad detection name globally.

## Limitations

- Windows x64 only
- Targets must be x64
- Only `nvapi64.dll` is hooked
- Protected or anti-cheat-enabled games may block injection
- If a game resolved and cached NVAPI before injection, this tool may not affect that cached pointer

## Build

The GitHub Actions workflow builds directly with the Visual C++ compiler on a Windows runner.

Manual local builds require the Visual Studio C++ toolchain.
