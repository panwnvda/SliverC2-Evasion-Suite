/*
 * mask.c — DISABLED for Sliver.
 *
 * Crystal Kit's sleep mask XOR-encrypts the beacon's code region while it sleeps.
 * In Sliver, Go goroutines continue running during any sleep/wait call, so the
 * masked region would be accessed mid-encryption and crash immediately.
 *
 * SleepKit (/home/kali/sleepkit/) provides sleep masking as a separate host
 * process for Sliver shellcode — use that instead.
 */
#include "loader.h"

void mask_sleep(uint32_t ms)  { (void)ms; }
void mask_encode(void)        {}
void mask_decode(void)        {}
