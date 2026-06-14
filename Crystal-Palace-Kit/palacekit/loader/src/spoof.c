/*
 * spoof.c — DISABLED for Sliver.
 *
 * Crystal Kit spoofs call stacks on sleep to defeat call-stack-based EDR scanning.
 * Relies on the same trampoline hooks that hooks.c disables for Sliver.
 * The Go runtime's goroutine scheduler generates non-spoofable stack traces anyway.
 */
#include "loader.h"

void spoof_init(void)  {}
void spoof_sleep(void) {}
