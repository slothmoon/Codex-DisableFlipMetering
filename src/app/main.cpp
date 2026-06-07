#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <atomic>
#include <cwctype>
#include <cstdint>
#include <iterator>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace
{
constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kIdEditWhitelist = 1001;
constexpr UINT kIdViewLog = 1002;
constexpr UINT kIdPauseWatching = 1003;
constexpr UINT kIdStartWithWindows = 1004;
constexpr UINT kIdExit = 1005;
constexpr UINT kIdSave = 2001;
constexpr UINT kIdCancel = 2002;
constexpr UINT kIdAddExe = 2003;
constexpr UINT kIdClose = 2004;
constexpr wchar_t kWindowClass[] = L"FlipConfigBypassTray";
constexpr wchar_t kEditorClass[] = L"FlipConfigBypassEditor";
constexpr wchar_t kLogClass[] = L"FlipConfigBypassLog";
constexpr wchar_t kTaskName[] = L"FlipConfigBypass";

HINSTANCE g_instance = nullptr;
HWND g_window = nullptr;
NOTIFYICONDATAW g_tray{};
std::atomic<bool> g_running{ true };
std::atomic<bool> g_paused{ false };
std::thread g_watcherThread;
std::mutex g_stateMutex;
std::vector<std::wstring> g_whitelist;
std::unordered_set<DWORD> g_attemptedPids;
std::wstring g_exePath;
std::wstring g_exeDir;
std::wstring g_payloadPath;
std::wstring g_whitelistPath;
std::wstring g_logPath;

std::wstring toLower(std::wstring value)
{
    for (wchar_t& ch : value)
        ch = static_cast<wchar_t>(towlower(ch));
    return value;
}

std::wstring trim(std::wstring value)
{
    const wchar_t* whitespace = L" \t\r\n";
    const size_t first = value.find_first_not_of(whitespace);
    if (first == std::wstring::npos)
        return {};
    const size_t last = value.find_last_not_of(whitespace);
    return value.substr(first, last - first + 1);
}

std::wstring fileNameFromPath(const std::wstring& path)
{
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

std::wstring joinPath(const std::wstring& dir, const std::wstring& name)
{
    std::wstring result = dir;
    if (!result.empty() && result.back() != L'\\')
        result.push_back(L'\\');
    result += name;
    return result;
}

std::string wideToUtf8(const std::wstring& text)
{
    if (text.empty())
        return {};

    const int size = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring utf8ToWide(const std::string& text)
{
    if (text.empty())
        return {};

    const int size = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), result.data(), size);
    return result;
}

std::wstring readTextFile(const std::wstring& path)
{
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return {};

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0)
    {
        CloseHandle(file);
        return {};
    }

    std::string bytes(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
    bytes.resize(read);
    CloseHandle(file);
    return utf8ToWide(bytes);
}

bool writeTextFile(const std::wstring& path, const std::wstring& text)
{
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;

    const std::string bytes = wideToUtf8(text);
    DWORD written = 0;
    const BOOL ok = WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
    CloseHandle(file);
    return ok && written == bytes.size();
}

void appendLog(const std::wstring& message)
{
    SYSTEMTIME time{};
    GetLocalTime(&time);

    wchar_t line[1024]{};
    swprintf_s(line, L"[%02u:%02u:%02u] %s\r\n", time.wHour, time.wMinute, time.wSecond, message.c_str());

    const std::string bytes = wideToUtf8(line);
    HANDLE file = CreateFileW(g_logPath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return;

    DWORD written = 0;
    WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
    CloseHandle(file);
}

void ensureDefaultFiles()
{
    if (GetFileAttributesW(g_whitelistPath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        writeTextFile(g_whitelistPath,
            L"# One executable name or full path per line.\r\n"
            L"# Example:\r\n"
            L"# GTA5.exe\r\n");
    }

    if (GetFileAttributesW(g_logPath.c_str()) == INVALID_FILE_ATTRIBUTES)
        writeTextFile(g_logPath, L"");
}

void loadWhitelist()
{
    std::vector<std::wstring> entries;
    std::wstring content = readTextFile(g_whitelistPath);
    size_t start = 0;
    while (start <= content.size())
    {
        const size_t end = content.find_first_of(L"\r\n", start);
        std::wstring line = trim(content.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start));
        if (!line.empty() && line[0] != L'#')
            entries.push_back(line);

        if (end == std::wstring::npos)
            break;
        start = content.find_first_not_of(L"\r\n", end);
        if (start == std::wstring::npos)
            break;
    }

    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_whitelist = std::move(entries);
}

std::vector<std::wstring> whitelistSnapshot()
{
    std::lock_guard<std::mutex> lock(g_stateMutex);
    return g_whitelist;
}

bool pidWasAttempted(DWORD pid)
{
    std::lock_guard<std::mutex> lock(g_stateMutex);
    return g_attemptedPids.find(pid) != g_attemptedPids.end();
}

void markPidAttempted(DWORD pid)
{
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_attemptedPids.insert(pid);
}

void pruneAttemptedPids(const std::unordered_set<DWORD>& livePids)
{
    std::lock_guard<std::mutex> lock(g_stateMutex);
    for (auto it = g_attemptedPids.begin(); it != g_attemptedPids.end();)
    {
        if (livePids.find(*it) == livePids.end())
            it = g_attemptedPids.erase(it);
        else
            ++it;
    }
}

bool matchesWhitelist(const std::vector<std::wstring>& whitelist, const std::wstring& exeName, const std::wstring& fullPath)
{
    const std::wstring exeLower = toLower(exeName);
    const std::wstring pathLower = toLower(fullPath);

    for (const std::wstring& entry : whitelist)
    {
        const std::wstring item = toLower(trim(entry));
        if (item.empty())
            continue;

        if (item.find(L'\\') != std::wstring::npos || item.find(L'/') != std::wstring::npos)
        {
            if (pathLower == item)
                return true;
        }
        else if (exeLower == item)
        {
            return true;
        }
    }

    return false;
}

std::wstring processPath(DWORD pid)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process)
        return {};

    wchar_t path[MAX_PATH * 4]{};
    DWORD size = static_cast<DWORD>(std::size(path));
    std::wstring result;
    if (QueryFullProcessImageNameW(process, 0, path, &size))
        result.assign(path, size);

    CloseHandle(process);
    return result;
}

bool isWow64ProcessCompat(HANDLE process, bool& isWow64)
{
    isWow64 = false;
    using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    auto isWow64Process2 = reinterpret_cast<IsWow64Process2Fn>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));

    if (isWow64Process2)
    {
        USHORT processMachine = 0;
        USHORT nativeMachine = 0;
        if (!isWow64Process2(process, &processMachine, &nativeMachine))
            return false;
        isWow64 = processMachine != IMAGE_FILE_MACHINE_UNKNOWN;
        return true;
    }

    BOOL wow64 = FALSE;
    if (!IsWow64Process(process, &wow64))
        return false;
    isWow64 = wow64 == TRUE;
    return true;
}

std::wstring lastErrorText(DWORD error)
{
    wchar_t* buffer = nullptr;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    std::wstring text = buffer ? trim(buffer) : L"unknown error";
    if (buffer)
        LocalFree(buffer);
    return text;
}

bool injectPayload(DWORD pid, const std::wstring& exeName)
{
    if (GetFileAttributesW(g_payloadPath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        appendLog(exeName + L" (PID " + std::to_wstring(pid) + L") - failed, payload DLL missing");
        return false;
    }

    HANDLE process = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid);
    if (!process)
    {
        appendLog(exeName + L" (PID " + std::to_wstring(pid) + L") - failed, " + lastErrorText(GetLastError()));
        return false;
    }

    bool isWow64 = false;
    if (isWow64ProcessCompat(process, isWow64) && isWow64)
    {
        CloseHandle(process);
        appendLog(exeName + L" (PID " + std::to_wstring(pid) + L") - failed, payload architecture mismatch");
        return false;
    }

    const size_t bytes = (g_payloadPath.size() + 1) * sizeof(wchar_t);
    void* remotePath = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath)
    {
        appendLog(exeName + L" (PID " + std::to_wstring(pid) + L") - failed, " + lastErrorText(GetLastError()));
        CloseHandle(process);
        return false;
    }

    bool ok = WriteProcessMemory(process, remotePath, g_payloadPath.c_str(), bytes, nullptr) == TRUE;
    if (ok)
    {
        auto loadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
        HANDLE thread = CreateRemoteThread(process, nullptr, 0, loadLibrary, remotePath, 0, nullptr);
        if (thread)
        {
            WaitForSingleObject(thread, 10000);
            DWORD exitCode = 0;
            GetExitCodeThread(thread, &exitCode);
            ok = exitCode != 0;
            CloseHandle(thread);
        }
        else
        {
            ok = false;
        }
    }

    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
    CloseHandle(process);

    if (ok)
        appendLog(exeName + L" (PID " + std::to_wstring(pid) + L") - injected OK");
    else
        appendLog(exeName + L" (PID " + std::to_wstring(pid) + L") - failed, " + lastErrorText(error));

    return ok;
}

void watcherLoop()
{
    while (g_running)
    {
        if (!g_paused)
        {
            const std::vector<std::wstring> whitelist = whitelistSnapshot();
            std::unordered_set<DWORD> livePids;
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot != INVALID_HANDLE_VALUE)
            {
                PROCESSENTRY32W entry{};
                entry.dwSize = sizeof(entry);
                if (Process32FirstW(snapshot, &entry))
                {
                    do
                    {
                        livePids.insert(entry.th32ProcessID);
                        if (pidWasAttempted(entry.th32ProcessID))
                            continue;

                        std::wstring fullPath = processPath(entry.th32ProcessID);
                        std::wstring exeName = fullPath.empty() ? entry.szExeFile : fileNameFromPath(fullPath);
                        if (matchesWhitelist(whitelist, exeName, fullPath))
                        {
                            markPidAttempted(entry.th32ProcessID);
                            injectPayload(entry.th32ProcessID, exeName);
                        }
                    } while (Process32NextW(snapshot, &entry));
                }

                CloseHandle(snapshot);
                pruneAttemptedPids(livePids);
            }
        }

        Sleep(2000);
    }
}

bool runHiddenProcess(std::wstring commandLine, DWORD* exitCode = nullptr)
{
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION processInfo{};
    if (!CreateProcessW(nullptr, commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &processInfo))
        return false;

    WaitForSingleObject(processInfo.hProcess, 15000);
    DWORD code = 1;
    GetExitCodeProcess(processInfo.hProcess, &code);
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
    if (exitCode)
        *exitCode = code;
    return code == 0;
}

bool startWithWindowsEnabled()
{
    DWORD exitCode = 1;
    runHiddenProcess(std::wstring(L"schtasks.exe /Query /TN \"") + kTaskName + L"\"", &exitCode);
    return exitCode == 0;
}

void setStartWithWindows(bool enabled)
{
    if (enabled)
    {
        std::wstring command = std::wstring(L"schtasks.exe /Create /TN \"") + kTaskName +
            L"\" /SC ONLOGON /TR \"\\\"" + g_exePath + L"\\\"\" /F";
        runHiddenProcess(command);
    }
    else
    {
        std::wstring command = std::wstring(L"schtasks.exe /Delete /TN \"") + kTaskName + L"\" /F";
        runHiddenProcess(command);
    }
}

void updateTrayTip()
{
    const size_t watched = whitelistSnapshot().size();
    std::wstring tip = L"Flip Config Bypass\r\n";
    tip += g_paused ? L"Paused" : L"Watching " + std::to_wstring(watched) + L" apps";
    wcsncpy_s(g_tray.szTip, tip.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &g_tray);
}

struct EditorState
{
    HWND edit = nullptr;
};

void resizeEditor(HWND hwnd, EditorState* state)
{
    RECT rect{};
    GetClientRect(hwnd, &rect);
    const int margin = 10;
    const int buttonY = rect.bottom - 38;
    MoveWindow(state->edit, margin, margin, rect.right - margin * 2, buttonY - margin * 2, TRUE);
    MoveWindow(GetDlgItem(hwnd, kIdAddExe), margin, buttonY, 90, 28, TRUE);
    MoveWindow(GetDlgItem(hwnd, kIdSave), rect.right - 170, buttonY, 75, 28, TRUE);
    MoveWindow(GetDlgItem(hwnd, kIdCancel), rect.right - 85, buttonY, 75, 28, TRUE);
}

LRESULT CALLBACK editorProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    auto* state = reinterpret_cast<EditorState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg)
    {
    case WM_NCCREATE:
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(
            reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams));
        return TRUE;
    case WM_CREATE:
        state = reinterpret_cast<EditorState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        state->edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", readTextFile(g_whitelistPath).c_str(),
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN,
            0, 0, 0, 0, hwnd, nullptr, g_instance, nullptr);
        CreateWindowW(L"BUTTON", L"Add EXE...", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(kIdAddExe), g_instance, nullptr);
        CreateWindowW(L"BUTTON", L"Save", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(kIdSave), g_instance, nullptr);
        CreateWindowW(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(kIdCancel), g_instance, nullptr);
        resizeEditor(hwnd, state);
        return 0;
    case WM_SIZE:
        if (state && state->edit)
            resizeEditor(hwnd, state);
        return 0;
    case WM_COMMAND:
        if (LOWORD(wparam) == kIdAddExe)
        {
            wchar_t file[MAX_PATH * 4]{};
            OPENFILENAMEW ofn{};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
            ofn.lpstrFile = file;
            ofn.nMaxFile = static_cast<DWORD>(std::size(file));
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileNameW(&ofn))
            {
                const int len = GetWindowTextLengthW(state->edit);
                SendMessageW(state->edit, EM_SETSEL, len, len);
                std::wstring line = std::wstring(len > 0 ? L"\r\n" : L"") + file;
                SendMessageW(state->edit, EM_REPLACESEL, TRUE, reinterpret_cast<LPARAM>(line.c_str()));
            }
        }
        else if (LOWORD(wparam) == kIdSave)
        {
            const int len = GetWindowTextLengthW(state->edit);
            std::wstring text(len + 1, L'\0');
            GetWindowTextW(state->edit, text.data(), len + 1);
            text.resize(len);
            writeTextFile(g_whitelistPath, text);
            loadWhitelist();
            updateTrayTip();
            DestroyWindow(hwnd);
        }
        else if (LOWORD(wparam) == kIdCancel)
        {
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

void showEditor(HWND owner)
{
    EditorState state{};
    HWND hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME, kEditorClass, L"Edit Whitelist",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 560, 420,
        owner, nullptr, g_instance, &state);

    EnableWindow(owner, FALSE);
    ShowWindow(hwnd, SW_SHOW);
    MSG msg{};
    while (IsWindow(hwnd) && GetMessageW(&msg, nullptr, 0, 0))
    {
        if (!IsDialogMessageW(hwnd, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);
}

LRESULT CALLBACK logProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    static HWND edit = nullptr;
    switch (msg)
    {
    case WM_CREATE:
        edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", readTextFile(g_logPath).c_str(),
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            10, 10, 560, 320, hwnd, nullptr, g_instance, nullptr);
        CreateWindowW(L"BUTTON", L"Close", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            495, 340, 75, 28, hwnd, reinterpret_cast<HMENU>(kIdClose), g_instance, nullptr);
        return 0;
    case WM_SIZE:
    {
        RECT rect{};
        GetClientRect(hwnd, &rect);
        MoveWindow(edit, 10, 10, rect.right - 20, rect.bottom - 52, TRUE);
        MoveWindow(GetDlgItem(hwnd, kIdClose), rect.right - 85, rect.bottom - 38, 75, 28, TRUE);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wparam) == kIdClose)
            DestroyWindow(hwnd);
        return 0;
    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

void showLog(HWND owner)
{
    HWND hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME, kLogClass, L"Log",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 600, 420,
        owner, nullptr, g_instance, nullptr);

    EnableWindow(owner, FALSE);
    ShowWindow(hwnd, SW_SHOW);
    MSG msg{};
    while (IsWindow(hwnd) && GetMessageW(&msg, nullptr, 0, 0))
    {
        if (!IsDialogMessageW(hwnd, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    EnableWindow(owner, TRUE);
    SetForegroundWindow(owner);
}

void showTrayMenu(HWND hwnd)
{
    updateTrayTip();

    POINT point{};
    GetCursorPos(&point);
    HMENU menu = CreatePopupMenu();
    const size_t watched = whitelistSnapshot().size();
    const std::wstring status = (g_paused ? L"Paused - " : L"Running - ") + std::to_wstring(watched) + L" apps watched";

    AppendMenuW(menu, MF_STRING | MF_DISABLED, 0, L"Flip Config Bypass");
    AppendMenuW(menu, MF_STRING | MF_DISABLED | (g_paused ? 0 : MF_CHECKED), 0, status.c_str());
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kIdEditWhitelist, L"Edit Whitelist...");
    AppendMenuW(menu, MF_STRING, kIdViewLog, L"View Log...");
    AppendMenuW(menu, MF_STRING | (g_paused ? MF_CHECKED : 0), kIdPauseWatching, L"Pause Watching");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING | (startWithWindowsEnabled() ? MF_CHECKED : 0), kIdStartWithWindows, L"Start with Windows");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kIdExit, L"Exit");

    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, point.x, point.y, 0, hwnd, nullptr);
    DestroyMenu(menu);
}

void addTrayIcon(HWND hwnd)
{
    g_tray.cbSize = sizeof(g_tray);
    g_tray.hWnd = hwnd;
    g_tray.uID = 1;
    g_tray.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_tray.uCallbackMessage = kTrayMessage;
    g_tray.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wcsncpy_s(g_tray.szTip, L"Flip Config Bypass", _TRUNCATE);
    Shell_NotifyIconW(NIM_ADD, &g_tray);
    updateTrayTip();
}

void removeTrayIcon()
{
    Shell_NotifyIconW(NIM_DELETE, &g_tray);
}

LRESULT CALLBACK windowProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg)
    {
    case kTrayMessage:
        if (lparam == WM_RBUTTONUP || lparam == WM_LBUTTONUP)
            showTrayMenu(hwnd);
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wparam))
        {
        case kIdEditWhitelist:
            showEditor(hwnd);
            return 0;
        case kIdViewLog:
            showLog(hwnd);
            return 0;
        case kIdPauseWatching:
            g_paused = !g_paused.load();
            updateTrayTip();
            return 0;
        case kIdStartWithWindows:
            setStartWithWindows(!startWithWindowsEnabled());
            return 0;
        case kIdExit:
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_DESTROY:
        g_running = false;
        removeTrayIcon();
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

bool registerClasses()
{
    WNDCLASSW wc{};
    wc.lpfnWndProc = windowProc;
    wc.hInstance = g_instance;
    wc.lpszClassName = kWindowClass;
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    if (!RegisterClassW(&wc))
        return false;

    wc = {};
    wc.lpfnWndProc = editorProc;
    wc.hInstance = g_instance;
    wc.lpszClassName = kEditorClass;
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    if (!RegisterClassW(&wc))
        return false;

    wc = {};
    wc.lpfnWndProc = logProc;
    wc.hInstance = g_instance;
    wc.lpszClassName = kLogClass;
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    return RegisterClassW(&wc) != 0;
}

void initPaths()
{
    wchar_t path[MAX_PATH * 4]{};
    GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
    g_exePath = path;
    g_exeDir = g_exePath.substr(0, g_exePath.find_last_of(L"\\/"));
    g_payloadPath = joinPath(g_exeDir, L"FlipConfigPayload.dll");
    g_whitelistPath = joinPath(g_exeDir, L"whitelist.txt");
    g_logPath = joinPath(g_exeDir, L"FlipConfigBypass.log");
}
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int)
{
    g_instance = instance;
    initPaths();
    ensureDefaultFiles();
    loadWhitelist();

    if (!registerClasses())
        return 1;

    g_window = CreateWindowW(kWindowClass, L"Flip Config Bypass", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        nullptr, nullptr, g_instance, nullptr);
    if (!g_window)
        return 1;

    addTrayIcon(g_window);
    g_watcherThread = std::thread(watcherLoop);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    g_running = false;
    if (g_watcherThread.joinable())
        g_watcherThread.join();

    return 0;
}
