#include <windows.h>
#include <tlhelp32.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <mutex>
#include <string>
#include <unordered_set>

#include "../shared/flip_config.h"

using NvApiQueryInterface = void* (__cdecl*)(unsigned int interfaceId);
using GetProcAddressFn = FARPROC(WINAPI*)(HMODULE module, LPCSTR procName);

namespace
{
std::atomic<NvApiQueryInterface> g_realNvApiQueryInterface{ nullptr };
std::atomic<GetProcAddressFn> g_realGetProcAddress{ ::GetProcAddress };
std::atomic<bool> g_running{ true };
std::mutex g_scanMutex;
std::unordered_set<HMODULE> g_scannedModules;

std::wstring toLower(std::wstring value)
{
    for (wchar_t& ch : value)
        ch = static_cast<wchar_t>(std::towlower(ch));
    return value;
}

std::wstring moduleBaseName(HMODULE module)
{
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(module, path, MAX_PATH))
        return {};

    std::wstring name(path);
    const size_t slash = name.find_last_of(L"\\/");
    if (slash != std::wstring::npos)
        name.erase(0, slash + 1);
    return toLower(name);
}

bool isNvApiModule(HMODULE module)
{
    const std::wstring name = moduleBaseName(module);
    return name == L"nvapi64.dll" || name == L"nvapi.dll";
}

void* __cdecl hookedNvApiQueryInterface(unsigned int interfaceId)
{
    if (interfaceId == kNvApiD3D12SetFlipConfigId)
        return nullptr;

    NvApiQueryInterface realNvApiQueryInterface = g_realNvApiQueryInterface.load(std::memory_order_acquire);
    return realNvApiQueryInterface ? realNvApiQueryInterface(interfaceId) : nullptr;
}

FARPROC WINAPI hookedGetProcAddress(HMODULE module, LPCSTR procName)
{
    GetProcAddressFn realGetProcAddress = g_realGetProcAddress.load(std::memory_order_acquire);
    FARPROC proc = realGetProcAddress(module, procName);

    if (procName && reinterpret_cast<uintptr_t>(procName) > 0xFFFF &&
        std::strcmp(procName, "nvapi_QueryInterface") == 0 &&
        proc && isNvApiModule(module))
    {
        g_realNvApiQueryInterface.store(reinterpret_cast<NvApiQueryInterface>(proc), std::memory_order_release);
        return reinterpret_cast<FARPROC>(&hookedNvApiQueryInterface);
    }

    return proc;
}

bool isReadablePeImage(HMODULE module)
{
    if (!module)
        return false;

    auto* base = reinterpret_cast<const std::uint8_t*>(module);
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        return false;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE;
}

bool patchImport(HMODULE module, const char* importedModuleName, const char* procName, void* replacement, void** original)
{
    if (!isReadablePeImage(module))
        return false;

    auto* base = reinterpret_cast<std::uint8_t*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.VirtualAddress || !importDir.Size)
        return false;

    bool patched = false;
    auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + importDir.VirtualAddress);
    for (; desc->Name; ++desc)
    {
        const char* dllName = reinterpret_cast<const char*>(base + desc->Name);
        if (_stricmp(dllName, importedModuleName) != 0 || !desc->OriginalFirstThunk)
            continue;

        auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
        auto* origThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk);

        for (; origThunk->u1.AddressOfData; ++origThunk, ++thunk)
        {
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal))
                continue;

            auto* importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + origThunk->u1.AddressOfData);
            if (std::strcmp(reinterpret_cast<const char*>(importByName->Name), procName) != 0)
                continue;

            void* current = reinterpret_cast<void*>(thunk->u1.Function);
            if (current == replacement)
                continue;

            DWORD oldProtect = 0;
            if (!VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect))
                continue;

            if (original && !*original)
                *original = current;
            thunk->u1.Function = reinterpret_cast<ULONG_PTR>(replacement);
            VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
            patched = true;
        }
    }

    return patched;
}

void patchModuleImports(HMODULE module)
{
    void* originalGetProc = nullptr;
    const char* loaderModules[] = {
        "KERNEL32.dll",
        "KERNELBASE.dll",
        "api-ms-win-core-libraryloader-l1-2-0.dll"
    };

    for (const char* loaderModule : loaderModules)
    {
        originalGetProc = nullptr;
        if (patchImport(module, loaderModule, "GetProcAddress", reinterpret_cast<void*>(&hookedGetProcAddress), &originalGetProc) && originalGetProc)
            g_realGetProcAddress.store(reinterpret_cast<GetProcAddressFn>(originalGetProc), std::memory_order_release);
    }

    void* originalNvQuery = nullptr;
    if (patchImport(module, "nvapi64.dll", "nvapi_QueryInterface", reinterpret_cast<void*>(&hookedNvApiQueryInterface), &originalNvQuery) && originalNvQuery)
        g_realNvApiQueryInterface.store(reinterpret_cast<NvApiQueryInterface>(originalNvQuery), std::memory_order_release);

    originalNvQuery = nullptr;
    if (patchImport(module, "nvapi.dll", "nvapi_QueryInterface", reinterpret_cast<void*>(&hookedNvApiQueryInterface), &originalNvQuery) && originalNvQuery)
        g_realNvApiQueryInterface.store(reinterpret_cast<NvApiQueryInterface>(originalNvQuery), std::memory_order_release);
}

void scanAndPatchImports()
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE)
        return;

    std::lock_guard<std::mutex> lock(g_scanMutex);
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry))
    {
        do
        {
            HMODULE module = reinterpret_cast<HMODULE>(entry.modBaseAddr);
            if (g_scannedModules.insert(module).second)
                patchModuleImports(module);
        } while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
}

DWORD WINAPI workerThread(void*)
{
    for (int i = 0; g_running && i < 600; ++i)
    {
        scanAndPatchImports();
        Sleep(500);
    }

    return 0;
}
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, void*)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);

        HMODULE pinned = nullptr;
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(&DllMain),
            &pinned);

        HANDLE thread = CreateThread(nullptr, 0, workerThread, nullptr, 0, nullptr);
        if (thread)
            CloseHandle(thread);
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        g_running = false;
    }

    return TRUE;
}
