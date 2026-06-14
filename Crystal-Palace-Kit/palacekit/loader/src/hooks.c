/*
 * hooks.c — DISABLED for Sliver.
 *
 * Crystal Kit uses hooks to intercept GetProcAddress / LoadLibraryW / ExitThread
 * for in-process DLL loading. Sliver shellcode runs inside the Go runtime, and
 * the Go scheduler preempts goroutines every ~10ms by sending signals. Installing
 * inline hooks corrupts the hook state between preemption points, causing crashes.
 *
 * All exported symbols are stubs so the COFF object links cleanly.
 */
#include "loader.h"

void hook_GetProcAddress(void) {}
void hook_LoadLibraryW(void)   {}
void hook_ExitThread(void)     {}
void install_hooks(void)       {}
void remove_hooks(void)        {}
