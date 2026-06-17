#pragma once
#include "loader.h"

int      __tag_setup_hooks(void);
int      __tag_setup_memory(void);
uint32_t PicoDataSize(const char *src);
uint32_t PicoCodeSize(const char *src);
void     PicoLoad(IMPORTFUNCS *funcs, const char *src, char *code, char *data);
void    *PicoGetExport(const char *src, const char *code, int tag);
void     setup_hooks(IMPORTFUNCS *funcs);
void     setup_memory(MEMORY_LAYOUT *layout);

/* PICO runtime hash table lookup — set populated by addhook directives.
 * Returns the hook function pointer for the given ROR13 hash, or NULL.
 * Operators wire this to a custom GetProcAddress-style intrinsic that
 * checks for a hook before falling through to the real API resolver.   */
void *__resolve_hook(uint32_t hash);

/* Loader-side helper: tell __resolve_hook where the blob and loaded code
 * live so it can find the embedded hash table.                         */
void pico_set_bases(const char *blob, char *code);
