x64:
    load "bin/loader.x64.o"
        make pic +gofirst

    dfr "resolve" "ror13"

    generate $KEY   32
    generate $NONCE 12

    push $DLL
        chacha20 $KEY $NONCE
        preplen
        link "dll"
    push $KEY
        preplen
        link "mask"
    push $NONCE
        preplen
        link "nonce"

    run "pico.spec"
        link "pico"

    export
