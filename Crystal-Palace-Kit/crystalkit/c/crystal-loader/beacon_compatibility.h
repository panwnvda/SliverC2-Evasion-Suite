/*
 * Cobalt Strike 4.x BOF compatibility layer — header
 *
 * Allows Crystal Palace PICO blobs (originally built for CS BOF) to run
 * inside Sliver without recompilation. Built off the beacon.h provided
 * for CS BOF development.
 *
 * Source: TrustedSec/CS-Situational-Awareness-BOF (MIT) / nickswink / rasta-mouse
 */
#ifndef BEACON_COMPATIBILITY_H_
#define BEACON_COMPATIBILITY_H_

#include <windows.h>
#include <stdint.h>

extern unsigned char* InternalFunctions[30][2];

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} formatp;

void    BeaconDataParse(datap *parser, char *buffer, int size);
int     BeaconDataInt(datap *parser);
short   BeaconDataShort(datap *parser);
int     BeaconDataLength(datap *parser);
char   *BeaconDataExtract(datap *parser, int *size);

void    BeaconFormatAlloc(formatp *format, int maxsz);
void    BeaconFormatReset(formatp *format);
void    BeaconFormatFree(formatp *format);
void    BeaconFormatAppend(formatp *format, char *text, int len);
void    BeaconFormatPrintf(formatp *format, char *fmt, ...);
char   *BeaconFormatToString(formatp *format, int *size);
void    BeaconFormatInt(formatp *format, int value);

#define CALLBACK_OUTPUT      0x00
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

void    BeaconPrintf(int type, char *fmt, ...);
void    BeaconOutput(int type, char *data, int len);

BOOL    BeaconUseToken(HANDLE token);
void    BeaconRevertToken(void);
BOOL    BeaconIsAdmin(void);

void    BeaconGetSpawnTo(BOOL x86, char *buffer, int length);
BOOL    BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                                    STARTUPINFO *sInfo,
                                    PROCESS_INFORMATION *pInfo);
void    BeaconInjectProcess(HANDLE hProc, int pid, char *payload, int p_len,
                            int p_offset, char *arg, int a_len);
void    BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pInfo,
                                     char *payload, int p_len,
                                     int p_offset, char *arg, int a_len);
void    BeaconCleanupProcess(PROCESS_INFORMATION *pInfo);

BOOL    toWideChar(char *src, wchar_t *dst, int max);
uint32_t swap_endianness(uint32_t indata);

char   *BeaconGetOutputData(int *outsize);

#endif /* BEACON_COMPATIBILITY_H_ */
