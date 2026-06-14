/*
 * Cobalt Strike 4.x BOF compatibility layer — implementation
 *
 * Allows Crystal Palace PICO blobs (originally built for CS BOF) to run
 * inside Sliver without recompilation.
 *
 * Source: TrustedSec/CS-Situational-Awareness-BOF (MIT) / nickswink / rasta-mouse
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#include "beacon_compatibility.h"

#define DEFAULTPROCESSNAME "rundll32.exe"
#ifdef _WIN64
#define X86PATH "SysWOW64"
#define X64PATH "System32"
#else
#define X86PATH "System32"
#define X64PATH "sysnative"
#endif

unsigned char* InternalFunctions[30][2] = {
    {(unsigned char*)"BeaconDataParse",              (unsigned char*)BeaconDataParse},
    {(unsigned char*)"BeaconDataInt",                (unsigned char*)BeaconDataInt},
    {(unsigned char*)"BeaconDataShort",              (unsigned char*)BeaconDataShort},
    {(unsigned char*)"BeaconDataLength",             (unsigned char*)BeaconDataLength},
    {(unsigned char*)"BeaconDataExtract",            (unsigned char*)BeaconDataExtract},
    {(unsigned char*)"BeaconFormatAlloc",            (unsigned char*)BeaconFormatAlloc},
    {(unsigned char*)"BeaconFormatReset",            (unsigned char*)BeaconFormatReset},
    {(unsigned char*)"BeaconFormatFree",             (unsigned char*)BeaconFormatFree},
    {(unsigned char*)"BeaconFormatAppend",           (unsigned char*)BeaconFormatAppend},
    {(unsigned char*)"BeaconFormatPrintf",           (unsigned char*)BeaconFormatPrintf},
    {(unsigned char*)"BeaconFormatToString",         (unsigned char*)BeaconFormatToString},
    {(unsigned char*)"BeaconFormatInt",              (unsigned char*)BeaconFormatInt},
    {(unsigned char*)"BeaconPrintf",                 (unsigned char*)BeaconPrintf},
    {(unsigned char*)"BeaconOutput",                 (unsigned char*)BeaconOutput},
    {(unsigned char*)"BeaconUseToken",               (unsigned char*)BeaconUseToken},
    {(unsigned char*)"BeaconRevertToken",            (unsigned char*)BeaconRevertToken},
    {(unsigned char*)"BeaconIsAdmin",                (unsigned char*)BeaconIsAdmin},
    {(unsigned char*)"BeaconGetSpawnTo",             (unsigned char*)BeaconGetSpawnTo},
    {(unsigned char*)"BeaconSpawnTemporaryProcess",  (unsigned char*)BeaconSpawnTemporaryProcess},
    {(unsigned char*)"BeaconInjectProcess",          (unsigned char*)BeaconInjectProcess},
    {(unsigned char*)"BeaconInjectTemporaryProcess", (unsigned char*)BeaconInjectTemporaryProcess},
    {(unsigned char*)"BeaconCleanupProcess",         (unsigned char*)BeaconCleanupProcess},
    {(unsigned char*)"toWideChar",                   (unsigned char*)toWideChar},
    {(unsigned char*)"LoadLibraryA",                 (unsigned char*)LoadLibraryA},
    {(unsigned char*)"GetProcAddress",               (unsigned char*)GetProcAddress},
    {(unsigned char*)"GetModuleHandleA",             (unsigned char*)GetModuleHandleA},
    {(unsigned char*)"FreeLibrary",                  (unsigned char*)FreeLibrary},
    {(unsigned char*)"__C_specific_handler",         NULL}
};

/* ── output accumulator ─────────────────────────────────────────────────── */

static char *beacon_output       = NULL;
static int   beacon_output_size  = 0;
static int   beacon_output_off   = 0;

/* ── data parsing ───────────────────────────────────────────────────────── */

void BeaconDataParse(datap *parser, char *buffer, int size)
{
    if (!parser || !buffer) return;
    parser->original = buffer;
    parser->buffer   = buffer + 4;
    parser->length   = size - 4;
    parser->size     = size - 4;
}

int BeaconDataInt(datap *parser)
{
    if (!parser || parser->length < 4) return 0;
    int32_t v = 0;
    memcpy(&v, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return (int)v;
}

short BeaconDataShort(datap *parser)
{
    if (!parser || parser->length < 2) return 0;
    int16_t v = 0;
    memcpy(&v, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return (short)v;
}

int BeaconDataLength(datap *parser)
{
    return parser ? parser->length : 0;
}

char *BeaconDataExtract(datap *parser, int *size)
{
    if (!parser || parser->length < 4) return NULL;
    uint32_t length = 0;
    memcpy(&length, parser->buffer, 4);
    parser->buffer += 4;
    char *out = parser->buffer;
    parser->length -= 4;
    parser->length -= (int)length;
    parser->buffer += length;
    if (size) *size = (int)length;
    return out;
}

/* ── format API ─────────────────────────────────────────────────────────── */

void BeaconFormatAlloc(formatp *format, int maxsz)
{
    if (!format) return;
    format->original = calloc(maxsz, 1);
    format->buffer   = format->original;
    format->length   = 0;
    format->size     = maxsz;
}

void BeaconFormatReset(formatp *format)
{
    if (!format) return;
    memset(format->original, 0, format->size);
    format->buffer = format->original;
    format->length = format->size;
}

void BeaconFormatFree(formatp *format)
{
    if (!format) return;
    if (format->original) { free(format->original); format->original = NULL; }
    format->buffer = NULL;
    format->length = 0;
    format->size   = 0;
}

void BeaconFormatAppend(formatp *format, char *text, int len)
{
    if (!format || !text) return;
    memcpy(format->buffer, text, len);
    format->buffer += len;
    format->length += len;
}

void BeaconFormatPrintf(formatp *format, char *fmt, ...)
{
    if (!format || !fmt) return;
    int room = format->size - format->length;
    if (room <= 0) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(format->buffer, room, fmt, ap);
    va_end(ap);
    if (n > 0) {
        format->length += n;
        format->buffer += n;
    }
}

char *BeaconFormatToString(formatp *format, int *size)
{
    if (!format || !size) return NULL;
    *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp *format, int value)
{
    if (!format || format->length + 4 > format->size) return;
    uint32_t out = swap_endianness((uint32_t)value);
    memcpy(format->buffer, &out, 4);
    format->length += 4;
    format->buffer += 4;
}

/* ── output functions ───────────────────────────────────────────────────── */

void BeaconPrintf(int type, char *fmt, ...)
{
    (void)type;
    if (!fmt) return;
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    char *tmp = realloc(beacon_output, beacon_output_size + len + 1);
    if (!tmp) return;
    beacon_output = tmp;
    memset(beacon_output + beacon_output_off, 0, len + 1);
    va_start(ap, fmt);
    len = vsnprintf(beacon_output + beacon_output_off, len + 1, fmt, ap);
    va_end(ap);
    beacon_output_size += len;
    beacon_output_off  += len;
}

void BeaconOutput(int type, char *data, int len)
{
    (void)type;
    if (!data) return;
    char *tmp = realloc(beacon_output, beacon_output_size + len + 1);
    if (!tmp) return;
    beacon_output = tmp;
    memset(beacon_output + beacon_output_off, 0, len + 1);
    memcpy(beacon_output + beacon_output_off, data, len);
    beacon_output_size += len;
    beacon_output_off  += len;
}

/* ── token functions ────────────────────────────────────────────────────── */

BOOL BeaconUseToken(HANDLE token)
{
    SetThreadToken(NULL, token);
    return TRUE;
}

void BeaconRevertToken(void)
{
    RevertToSelf();
}

BOOL BeaconIsAdmin(void)
{
    return FALSE;
}

/* ── spawn / inject (stubs) ─────────────────────────────────────────────── */

void BeaconGetSpawnTo(BOOL x86, char *buffer, int length)
{
    if (!buffer) return;
    const char *path = x86
        ? "C:\\Windows\\" X86PATH "\\" DEFAULTPROCESSNAME
        : "C:\\Windows\\" X64PATH "\\" DEFAULTPROCESSNAME;
    if ((int)strlen(path) >= length) return;
    memcpy(buffer, path, strlen(path));
}

BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                                  STARTUPINFO *sInfo,
                                  PROCESS_INFORMATION *pInfo)
{
    (void)ignoreToken;
    const char *path = x86
        ? "C:\\Windows\\" X86PATH "\\" DEFAULTPROCESSNAME
        : "C:\\Windows\\" X64PATH "\\" DEFAULTPROCESSNAME;
    return CreateProcessA(NULL, (char *)path, NULL, NULL,
                          TRUE, CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
}

void BeaconInjectProcess(HANDLE hProc, int pid, char *payload, int p_len,
                         int p_offset, char *arg, int a_len)
{
    (void)hProc; (void)pid; (void)payload; (void)p_len;
    (void)p_offset; (void)arg; (void)a_len;
}

void BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pInfo,
                                   char *payload, int p_len,
                                   int p_offset, char *arg, int a_len)
{
    (void)pInfo; (void)payload; (void)p_len;
    (void)p_offset; (void)arg; (void)a_len;
}

void BeaconCleanupProcess(PROCESS_INFORMATION *pInfo)
{
    if (pInfo) {
        CloseHandle(pInfo->hThread);
        CloseHandle(pInfo->hProcess);
    }
}

/* ── utility ────────────────────────────────────────────────────────────── */

BOOL toWideChar(char *src, wchar_t *dst, int max)
{
    if (max < (int)sizeof(wchar_t)) return FALSE;
    return MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS,
                               src, -1, dst, max / (int)sizeof(wchar_t));
}

uint32_t swap_endianness(uint32_t indata)
{
    uint32_t test = 0xaabbccdd;
    if (((unsigned char *)&test)[0] != 0xdd) return indata;
    return ((indata & 0x000000FF) << 24) |
           ((indata & 0x0000FF00) <<  8) |
           ((indata & 0x00FF0000) >>  8) |
           ((indata & 0xFF000000) >> 24);
}

char *BeaconGetOutputData(int *outsize)
{
    if (!outsize) return NULL;
    char *data       = beacon_output;
    *outsize         = beacon_output_size;
    beacon_output      = NULL;
    beacon_output_size = 0;
    beacon_output_off  = 0;
    return data;
}

#endif /* _WIN32 */
