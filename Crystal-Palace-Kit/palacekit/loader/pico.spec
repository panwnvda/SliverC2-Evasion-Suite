x64:
    ; PalaceKit pico spec — minimal PICO component for Sliver
    ;
    ; Mirrors rasta-mouse/Crystal-Kit loader/pico.spec.
    ; Crystal Palace would link this against libtcg.x64.zip and generate
    ; a full TCG PICO blob. We generate a simplified blob with two no-op
    ; exported functions (setup_hooks, setup_memory).

    load "bin/pico.x64.o"
        make object +disco

    load "bin/hooks.x64.o"
        merge

    load "bin/spoof.x64.o"
        merge

    load "bin/cfg.x64.o"
        merge

    load "bin/cleanup.x64.o"
        merge

    exportfunc "setup_hooks"  "__tag_setup_hooks"
    exportfunc "setup_memory" "__tag_setup_memory"

    ; addhook directives are no-ops (hooks disabled for Sliver)
    addhook "KERNEL32$GetProcAddress" "_GetProcAddress"
    addhook "KERNEL32$LoadLibraryW"   "_LoadLibraryW"
    addhook "KERNEL32$ExitThread"     "_ExitThread"

    export
