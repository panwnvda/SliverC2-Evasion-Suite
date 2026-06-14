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
