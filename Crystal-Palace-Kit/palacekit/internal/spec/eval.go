package spec

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/chacha20"

	"palacekit/internal/coff"
	"palacekit/internal/link"
)

// Result is the output of evaluating a spec file.
type Result struct {
	Image  *link.LinkedImage
	Output []byte // final assembled shellcode blob
}

// Evaluator processes a Crystal Kit spec file.
type Evaluator struct {
	BaseDir  string // resolve relative paths from here (CWD)
	Verbose  bool
	initVars map[string][]byte // pre-set variables (e.g. $DLL = shellcode bytes)
}

// SetVar pre-sets a spec variable before evaluation (e.g. $DLL with shellcode bytes).
func (e *Evaluator) SetVar(name string, data []byte) {
	if e.initVars == nil {
		e.initVars = make(map[string][]byte)
	}
	e.initVars[name] = data
}

type stackItem struct {
	data    []byte
	name    string // for `link "name"`
}

type evalState struct {
	linker   *link.Linker
	stack    []stackItem
	mask     []byte
	vars     map[string][]byte
	exports  map[string]int // exportfunc tag → code offset
	tagSeq   int
	tagNames map[string]int // exportfunc name → tag id

	// Crystal Palace DFR / hook state — populated by attach/preserve/addhook.
	// Passed to the linker at Finish() time so it can rewrite relocations.
	attachMap   map[string]string            // extern symbol → local hook symbol
	preserveMap map[string]map[string]bool   // extern symbol → set of containing functions exempt from attach
	addHooks    []link.AddHookEntry          // PICO runtime hook table entries
}

func (e *Evaluator) Run(specPath string) (*Result, error) {
	// Resolve spec path to absolute so BaseDir derivation works from any CWD.
	absSpec, err := filepath.Abs(specPath)
	if err != nil {
		return nil, fmt.Errorf("resolve spec path: %w", err)
	}
	data, err := os.ReadFile(absSpec)
	if err != nil {
		return nil, fmt.Errorf("read spec %s: %w", absSpec, err)
	}
	return e.eval(string(data), absSpec)
}

func (e *Evaluator) RunBytes(src string, specPath string) (*Result, error) {
	return e.eval(src, specPath)
}

func (e *Evaluator) eval(src string, specPath string) (*Result, error) {
	lines := strings.Split(src, "\n")

	st := &evalState{
		linker:      link.New(),
		vars:        make(map[string][]byte),
		exports:     make(map[string]int),
		tagNames:    make(map[string]int),
		attachMap:   make(map[string]string),
		preserveMap: make(map[string]map[string]bool),
	}
	// Copy pre-set variables (e.g. $DLL)
	for k, v := range e.initVars {
		st.vars[k] = v
	}

	baseDir := e.BaseDir
	if baseDir == "" {
		// Default: use the directory containing the spec file.
		// This makes `load "bin/loader.x64.o"` resolve relative to the spec.
		baseDir = filepath.Dir(specPath)
	}

	// Skip arch prefix lines ("x64:")
	active := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasSuffix(line, ":") {
			// Architecture selector
			active = strings.HasPrefix(strings.ToLower(line), "x64")
			continue
		}
		if !active {
			continue
		}

		if err := e.execLine(line, lines, st, baseDir, specPath); err != nil {
			return nil, fmt.Errorf("spec line %q: %w", line, err)
		}
	}

	// Pass DFR/hook config to the linker before finalization.
	if len(st.attachMap) > 0 {
		st.linker.SetAttachments(st.attachMap)
	}
	if len(st.preserveMap) > 0 {
		st.linker.SetPreserves(st.preserveMap)
	}
	if len(st.addHooks) > 0 {
		st.linker.SetAddHooks(st.addHooks)
	}

	img := st.linker.Finish()
	out, err := e.assemble(img, st)
	if err != nil {
		return nil, err
	}

	return &Result{Image: img, Output: out}, nil
}

func (e *Evaluator) execLine(line string, allLines []string, st *evalState, baseDir, specPath string) error {
	tokens := tokenize(line)
	if len(tokens) == 0 {
		return nil
	}

	switch tokens[0] {
	case "load":
		return e.cmdLoad(tokens, st, baseDir)
	case "merge":
		// handled as a modifier in load context — standalone is no-op
		return nil
	case "dfr":
		// dfr "resolve" "ror13" — register the resolve function name
		// We ignore this since our services.c always uses ror13
		return nil
	case "mergelib":
		return e.cmdMergeLib(tokens, st, baseDir)
	case "make":
		// make pic / make object — Crystal Palace compiler mode hints; no-op here
		return nil
	case "attach":
		return e.cmdAttach(tokens, st)
	case "preserve":
		return e.cmdPreserve(tokens, st)
	case "generate":
		return e.cmdGenerate(tokens, st)
	case "push":
		return e.cmdPush(tokens, st)
	case "xor":
		return e.cmdXor(tokens, st)
	case "chacha20":
		return e.cmdChaCha20(tokens, st)
	case "preplen":
		return e.cmdPrepLen(st)
	case "link":
		return e.cmdLink(tokens, st)
	case "run":
		return e.cmdRun(tokens, st, baseDir, specPath)
	case "exportfunc":
		return e.cmdExportFunc(tokens, st)
	case "addhook":
		return e.cmdAddHook(tokens, st)
	case "linkfunc":
		// linkfunc "sym" — treat binary blob's symbol as a function
		return nil
	case "export":
		// Final export directive — triggers assembly
		return nil
	default:
		if e.Verbose {
			fmt.Fprintf(os.Stderr, "[spec] unknown directive: %s\n", tokens[0])
		}
	}
	return nil
}

func (e *Evaluator) cmdLoad(tokens []string, st *evalState, baseDir string) error {
	if len(tokens) < 2 {
		return fmt.Errorf("load requires filename")
	}
	path := filepath.Join(baseDir, unquote(tokens[1]))

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("load %s: %w", path, err)
	}

	var modifiers []string
	for _, t := range tokens[2:] {
		modifiers = append(modifiers, t)
	}

	// If file looks like a COFF object, parse and merge
	if isCOFF(data) {
		obj, err := coff.Parse(data)
		if err != nil {
			return fmt.Errorf("parse COFF %s: %w", path, err)
		}
		return st.linker.MergeObject(obj, modifiers)
	}

	// Otherwise treat as raw binary (draugr.x64.bin etc.)
	// linkfunc or plain blob — append to code
	return st.linker.MergeRawCode(data)
}

func (e *Evaluator) cmdMergeLib(tokens []string, st *evalState, baseDir string) error {
	if len(tokens) < 2 {
		return fmt.Errorf("mergelib requires path")
	}
	path := filepath.Join(baseDir, unquote(tokens[1]))

	zr, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("mergelib open %s: %w", path, err)
	}
	defer zr.Close()

	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".o") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("mergelib extract %s: %w", f.Name, err)
		}
		var buf bytes.Buffer
		buf.ReadFrom(rc)
		rc.Close()

		obj, err := coff.Parse(buf.Bytes())
		if err != nil {
			if e.Verbose {
				fmt.Fprintf(os.Stderr, "[mergelib] skip %s: %v\n", f.Name, err)
			}
			continue
		}
		if err := st.linker.MergeObject(obj, nil); err != nil {
			return fmt.Errorf("mergelib merge %s: %w", f.Name, err)
		}
	}
	return nil
}

func (e *Evaluator) cmdGenerate(tokens []string, st *evalState) error {
	// generate $MASK N — generate N random bytes and store in $MASK variable
	if len(tokens) < 3 {
		return fmt.Errorf("generate requires variable and size")
	}
	varName := tokens[1]
	size := 0
	fmt.Sscanf(tokens[2], "%d", &size)
	if size <= 0 {
		return fmt.Errorf("generate size must be > 0")
	}

	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate random: %w", err)
	}
	st.vars[varName] = key
	if varName == "$MASK" {
		st.mask = key
	}
	return nil
}

func (e *Evaluator) cmdPush(tokens []string, st *evalState) error {
	// push $VAR
	if len(tokens) < 2 {
		return fmt.Errorf("push requires variable or section name")
	}
	ref := tokens[1]
	if strings.HasPrefix(ref, "$") {
		data, ok := st.vars[ref]
		if !ok {
			return fmt.Errorf("push: undefined variable %s", ref)
		}
		st.stack = append(st.stack, stackItem{data: clone(data)})
		return nil
	}
	// Named section reference
	if data, ok := st.linker.NamedSection(ref); ok {
		st.stack = append(st.stack, stackItem{data: clone(data)})
		return nil
	}
	return fmt.Errorf("push: unknown ref %s", ref)
}

func (e *Evaluator) cmdXor(tokens []string, st *evalState) error {
	// xor $MASK — XOR top of stack with mask variable
	if len(st.stack) == 0 {
		return fmt.Errorf("xor: empty stack")
	}
	if len(tokens) < 2 {
		return fmt.Errorf("xor requires mask variable")
	}
	mask, ok := st.vars[tokens[1]]
	if !ok {
		return fmt.Errorf("xor: undefined variable %s", tokens[1])
	}

	top := &st.stack[len(st.stack)-1]
	for i := range top.data {
		top.data[i] ^= mask[i%len(mask)]
	}
	return nil
}

func (e *Evaluator) cmdPrepLen(st *evalState) error {
	// prepend uint32 length to top of stack (RESOURCE struct format)
	if len(st.stack) == 0 {
		return fmt.Errorf("preplen: empty stack")
	}
	top := &st.stack[len(st.stack)-1]
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(top.data)))
	top.data = append(lenBuf, top.data...)
	return nil
}

func (e *Evaluator) cmdLink(tokens []string, st *evalState) error {
	// link "sectionname" — pop top of stack and store as named section
	if len(tokens) < 2 {
		return fmt.Errorf("link requires section name")
	}
	if len(st.stack) == 0 {
		return fmt.Errorf("link: empty stack")
	}
	name := unquote(tokens[1])
	top := st.stack[len(st.stack)-1]
	st.stack = st.stack[:len(st.stack)-1]
	st.linker.SetNamedSection(name, top.data)
	return nil
}

func (e *Evaluator) cmdRun(tokens []string, st *evalState, baseDir, parentSpec string) error {
	// run "pico.spec" / link "pico"
	// Runs sub-spec, assembles it, and pushes result onto stack
	if len(tokens) < 2 {
		return fmt.Errorf("run requires spec path")
	}
	subPath := filepath.Join(baseDir, unquote(tokens[1]))
	sub := &Evaluator{BaseDir: baseDir, Verbose: e.Verbose}
	result, err := sub.Run(subPath)
	if err != nil {
		return fmt.Errorf("run %s: %w", subPath, err)
	}
	st.stack = append(st.stack, stackItem{data: result.Output})
	return nil
}

func (e *Evaluator) cmdExportFunc(tokens []string, st *evalState) error {
	// exportfunc "funcName" "__tag_funcName"
	// Assigns a tag ID to the function, registers the C stub symbol
	if len(tokens) < 3 {
		return fmt.Errorf("exportfunc requires funcName and tagName")
	}
	funcName := unquote(tokens[1])
	tagName := unquote(tokens[2])

	tagID := st.tagSeq
	st.tagSeq++
	st.tagNames[funcName] = tagID
	st.tagNames[tagName] = tagID

	// The __tag_funcName symbol in the COFF returns this tag ID.
	// We register it so the linker knows the offset.
	_ = funcName
	_ = tagName
	return nil
}

// assemble builds the final output blob from the linked image.
// For a loader spec, the output is the PIC shellcode with named sections embedded.
// For a pico spec, the output is a PICO blob (simplified format).
func (e *Evaluator) assemble(img *link.LinkedImage, st *evalState) ([]byte, error) {
	// Build PICO blob for sub-specs that export functions
	if len(st.tagNames) > 0 {
		return buildPICO(img, st)
	}

	// For the main loader spec, assemble the full shellcode:
	// [entry stub][code][rdata][data][named sections embedded]
	return buildLoaderShellcode(img, st)
}

// debug
var Debug = false

// PICO blob format v2:
//   [4]  total_size
//   [4]  num_exports
//   [4]  num_hooks (addhook entries)
//   [4]  hooks_table_offset (relative to PICO start; 0 if num_hooks == 0)
//   [num_exports × {[4]tag [4]code_offset}]
//   [code bytes]
//   [num_hooks × {[4]ror13_hash [4]hook_code_offset}]   ← appended after code
// The PICO's __resolve_hook(hash) intrinsic reads the table from the blob
// header at runtime and returns the matching hook function pointer.
func buildPICO(img *link.LinkedImage, st *evalState) ([]byte, error) {
	// Build deduped export list: one entry per exportfunc declaration.
	// st.tagNames double-counts (funcName + tagName both map to the same id).
	type expEntry struct {
		name string
		tag  int
	}
	var exports []expEntry
	seen := make(map[int]bool)
	for name, tag := range st.tagNames {
		if seen[tag] {
			continue
		}
		// Prefer the actual function name (no "__tag_" prefix) — that's the
		// PICO export operators call. The "__tag_X" alias is a C helper.
		if strings.HasPrefix(name, "__tag_") {
			continue
		}
		exports = append(exports, expEntry{name: name, tag: tag})
		seen[tag] = true
	}
	// Backfill any tag that only had a __tag_X entry (no plain funcName).
	for name, tag := range st.tagNames {
		if seen[tag] {
			continue
		}
		exports = append(exports, expEntry{name: name, tag: tag})
		seen[tag] = true
	}

	numExports := len(exports)
	numHooks := len(st.addHooks)
	if Debug {
		fmt.Fprintf(os.Stderr, "[pico] buildPICO: %d exports, %d hooks\n", numExports, numHooks)
	}
	headerSize := 16
	tableOff := headerSize
	codeOff := tableOff + numExports*8
	codeLen := len(img.Code)
	hookTableOff := codeOff + codeLen
	hookTableSize := numHooks * 8
	total := hookTableOff + hookTableSize

	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:], uint32(total))
	binary.LittleEndian.PutUint32(buf[4:], uint32(numExports))
	binary.LittleEndian.PutUint32(buf[8:], uint32(numHooks))
	if numHooks > 0 {
		binary.LittleEndian.PutUint32(buf[12:], uint32(hookTableOff))
	}

	for i, ent := range exports {
		off := img.SymbolOffset(ent.name)
		if off < 0 {
			off = 0
		}
		binary.LittleEndian.PutUint32(buf[tableOff+i*8:], uint32(ent.tag))
		binary.LittleEndian.PutUint32(buf[tableOff+i*8+4:], uint32(codeOff+int(off)))
	}
	copy(buf[codeOff:], img.Code)

	// Append the runtime hook table — one entry per addhook directive.
	// Hook code offsets are absolute within the PICO blob so __resolve_hook
	// can return them as PICO-base + offset without further fix-up.
	for j, entry := range st.addHooks {
		hookOff := img.SymbolOffset(entry.HookSym)
		if hookOff < 0 {
			// Hook symbol not present — encode a 0 offset so the runtime
			// intrinsic returns NULL for this hash.
			hookOff = 0
		}
		binary.LittleEndian.PutUint32(buf[hookTableOff+j*8:], entry.Hash)
		binary.LittleEndian.PutUint32(buf[hookTableOff+j*8+4:], uint32(codeOff+int(hookOff)))
	}
	return buf, nil
}

// magic markers for named sections — must match constants in loader.h
var namedSectionMagic = map[string]uint32{
	"dll":   0xC001B008,
	"mask":  0xC001B009,
	"pico":  0xC001B007,
	"nonce": 0xC001B00A,
}

// buildLoaderShellcode assembles the main loader shellcode.
// Layout: [entry_stub 33][code][rdata][data][MAGIC_DLL][dll][MAGIC_MASK][mask][MAGIC_PICO][pico]
//
// Each named section is preceded by its 4-byte little-endian magic so that
// find_resource_by_magic() in loader.c can locate them without COFF relocs.
// The RESOURCE struct (uint32 len + bytes) is already embedded by the `preplen`
// spec directive, so we just need to prepend the magic and write the data.
func buildLoaderShellcode(img *link.LinkedImage, st *evalState) ([]byte, error) {
	codeSize := len(img.Code)
	rdataSize := len(img.RData)
	dataRegionOff := 33 + codeSize + rdataSize

	entryStub := buildEntryStub(uint32(dataRegionOff))

	var out bytes.Buffer
	out.Write(entryStub)
	out.Write(img.Code)
	out.Write(img.RData)
	out.Write(img.Data)

	// Append named sections, each preceded by a 4-byte magic marker.
	// find_resource_by_magic() scans for the magic and returns a pointer
	// to the byte immediately following it (= the RESOURCE struct).
	magicBuf := make([]byte, 4)
	for _, name := range []string{"dll", "mask", "nonce", "pico"} {
		d, ok := img.Named[name]
		if !ok || len(d) == 0 {
			continue
		}
		binary.LittleEndian.PutUint32(magicBuf, namedSectionMagic[name])
		out.Write(magicBuf)
		out.Write(d)
	}

	return out.Bytes(), nil
}

// buildEntryStub generates the 33-byte PIC entry stub.
// It gets the shellcode base address, adds dataOffset to get the data region pointer,
// passes it as RCX (arg1), then calls the entry at offset 0.
func buildEntryStub(dataOffset uint32) []byte {
	// E8 00000000   call .here
	// 58            pop rax        (rax = stub_base + 5)
	// 48 83 E8 05   sub rax, 5    (rax = stub_base)
	// 48 05 XX XX XX XX add rax, dataOffset
	// 48 89 C1      mov rcx, rax
	// 48 83 EC 28   sub rsp, 40   (shadow space)
	// E8 XX XX XX XX call +0       (call code[0] = go())
	// 48 83 C4 28   add rsp, 40
	// C3            ret
	stub := make([]byte, 33)
	stub[0] = 0xE8
	stub[1] = 0x00
	stub[2] = 0x00
	stub[3] = 0x00
	stub[4] = 0x00
	stub[5] = 0x58
	stub[6] = 0x48
	stub[7] = 0x83
	stub[8] = 0xE8
	stub[9] = 0x05
	stub[10] = 0x48
	stub[11] = 0x05
	binary.LittleEndian.PutUint32(stub[12:], dataOffset)
	stub[16] = 0x48
	stub[17] = 0x89
	stub[18] = 0xC1
	stub[19] = 0x48
	stub[20] = 0x83
	stub[21] = 0xEC
	stub[22] = 0x28
	stub[23] = 0xE8
	// call target: go() is at stub[33] = offset 0 in code after stub
	// PC after call = stub[28], target = stub[33], delta = 5
	binary.LittleEndian.PutUint32(stub[24:], uint32(5))
	stub[28] = 0x48
	stub[29] = 0x83
	stub[30] = 0xC4
	stub[31] = 0x28
	stub[32] = 0xC3
	return stub
}

func tokenize(line string) []string {
	var tokens []string
	var cur strings.Builder
	inQuote := false
	for _, c := range line {
		switch {
		case c == '"':
			if inQuote {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			inQuote = !inQuote
		case inQuote:
			cur.WriteRune(c)
		case c == ' ' || c == '\t':
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

func unquote(s string) string {
	return strings.Trim(s, `"'`)
}

// cmdAttach records a DFR rewrite: at link time, any unresolved external
// matching `extern` is resolved to the local hook symbol `localHook`.
//   attach "KERNEL32$VirtualAlloc" "_HookedVirtualAlloc"
func (e *Evaluator) cmdAttach(tokens []string, st *evalState) error {
	if len(tokens) < 3 {
		return fmt.Errorf("attach requires extern symbol and local hook name")
	}
	st.attachMap[unquote(tokens[1])] = unquote(tokens[2])
	return nil
}

// cmdPreserve exempts callsites inside a specific function from an attach
// rewrite. Used so the hook itself can still reach the original API.
//   preserve "KERNEL32$VirtualAlloc" "_HookedVirtualAlloc"
func (e *Evaluator) cmdPreserve(tokens []string, st *evalState) error {
	if len(tokens) < 3 {
		return fmt.Errorf("preserve requires extern symbol and containing function")
	}
	extern := unquote(tokens[1])
	containing := unquote(tokens[2])
	if st.preserveMap[extern] == nil {
		st.preserveMap[extern] = make(map[string]bool)
	}
	st.preserveMap[extern][containing] = true
	return nil
}

// cmdAddHook records a runtime hash → hook function entry that the spec
// assembler embeds into the PICO blob for __resolve_hook to consult.
//   addhook "KERNEL32$LoadLibraryA" "_LoadLibraryA"
func (e *Evaluator) cmdAddHook(tokens []string, st *evalState) error {
	if len(tokens) < 3 {
		return fmt.Errorf("addhook requires API symbol and local hook name")
	}
	apiSym := unquote(tokens[1])
	hookSym := unquote(tokens[2])

	// API symbol is "MODULE$FunctionName" — hash just the function name.
	dollar := strings.Index(apiSym, "$")
	funcName := apiSym
	if dollar >= 0 {
		funcName = apiSym[dollar+1:]
	}
	st.addHooks = append(st.addHooks, link.AddHookEntry{
		Hash:    ror13Hash(funcName),
		HookSym: hookSym,
	})
	return nil
}

// cmdChaCha20 encrypts top of stack with ChaCha20.
// Usage:  chacha20 $KEY $NONCE
//   $KEY    must be 32 bytes (use `generate $KEY 32`)
//   $NONCE  must be 12 bytes (use `generate $NONCE 12`)
// Stream cipher → output length == input length, preserving the RESOURCE layout.
func (e *Evaluator) cmdChaCha20(tokens []string, st *evalState) error {
	if len(st.stack) == 0 {
		return fmt.Errorf("chacha20: empty stack")
	}
	if len(tokens) < 3 {
		return fmt.Errorf("chacha20 requires $KEY and $NONCE variables")
	}
	key, ok := st.vars[tokens[1]]
	if !ok || len(key) != 32 {
		return fmt.Errorf("chacha20: $KEY must be 32 bytes (got %d)", len(key))
	}
	nonce, ok := st.vars[tokens[2]]
	if !ok || len(nonce) != 12 {
		return fmt.Errorf("chacha20: $NONCE must be 12 bytes (got %d)", len(nonce))
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return fmt.Errorf("chacha20 init: %w", err)
	}
	top := &st.stack[len(st.stack)-1]
	out := make([]byte, len(top.data))
	cipher.XORKeyStream(out, top.data)
	top.data = out
	return nil
}

// ror13Hash computes the standard ROR13 hash used by the loader's PEB walker.
// Must match the algorithm in services.c.
func ror13Hash(s string) uint32 {
	var h uint32
	for i := 0; i < len(s); i++ {
		h = (h >> 13) | (h << 19)
		h += uint32(s[i])
	}
	return h
}

func isCOFF(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	magic := binary.LittleEndian.Uint16(data)
	return magic == 0x8664 || magic == 0x014C // AMD64 or i386
}

func clone(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
