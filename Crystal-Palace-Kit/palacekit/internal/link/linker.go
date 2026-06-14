// COFF linker for PalaceKit.
// Produces [code][rdata][data] with optional named sections (dll, mask, pico).
//
// Two-pass design:
//   Pass 1 (MergeObject): append section bytes and register symbols.
//   Pass 2 (Finish):      apply all deferred relocations now that final sizes
//     are known, resolving cross-section REL32 displacements correctly.
//
// Named sections (dll, mask, pico) are populated via SetNamedSection() after
// all MergeObject calls. With the magic-marker approach in loader.c, no COFF
// relocations target named sections — they are simply appended to the output.
package link

import (
	"encoding/binary"
	"fmt"
	"strings"

	"palacekit/internal/coff"
)

// LinkedImage is the result of linking one or more COFF objects.
type LinkedImage struct {
	Code    []byte            // merged .text
	RData   []byte            // merged .rdata
	Data    []byte            // merged .data/.bss
	Named   map[string][]byte // named sections set via SetNamedSection
	Exports map[string]uint32 // export name → offset into Code
	symbols map[string]symbolEntry
}

// SymbolOffset returns the offset of a symbol in the Code region, or -1.
func (img *LinkedImage) SymbolOffset(name string) int64 {
	if img.symbols == nil {
		return -1
	}
	if e, ok := img.symbols[name]; ok && e.section == "text" {
		return int64(e.offset)
	}
	return -1
}

type symbolEntry struct {
	section string // "text", "rdata", "data", named-section name
	offset  uint32 // region-relative (0-based from start of region)
}

// pendingReloc stores a deferred relocation.
type pendingReloc struct {
	writeRegion string // "text", "rdata", "data", named-section name
	writeOff    uint32 // region-relative byte offset of field to patch
	symRegion   string // "" = unresolved extern
	symOff      uint32 // region-relative offset of target
	relocType   uint16
	addend      int64  // existing value at write site (for ADDR variants)
	pcAdj       uint32 // bytes field-start → next instruction (REL32 variants)
}

type Linker struct {
	code    []byte
	rdata   []byte
	data    []byte
	named   map[string][]byte

	exports map[string]uint32
	symbols map[string]symbolEntry
	pending []pendingReloc
}

func New() *Linker {
	return &Linker{
		named:   make(map[string][]byte),
		exports: make(map[string]uint32),
		symbols: make(map[string]symbolEntry),
	}
}

// MergeObject merges a parsed COFF object into the image (pass 1 only).
// modifiers: "pic", "+gofirst", "+optimize", "+disco", "object", "merge"
// Relocations are NOT applied here; call Finish() after all objects are merged.
func (l *Linker) MergeObject(obj *coff.Object, modifiers []string) error {
	sectionBase := make([]uint32, len(obj.Sections))
	sectionRegion := make([]string, len(obj.Sections))

	// Pass 1a: append section data, record region-relative base offsets.
	for i, sec := range obj.Sections {
		name := sec.Name
		ch := sec.Header.Characteristics

		switch {
		case strings.HasPrefix(name, ".text") || ch&coff.IMAGE_SCN_CNT_CODE != 0:
			sectionBase[i] = uint32(len(l.code))
			sectionRegion[i] = "text"
			l.code = append(l.code, sec.Data...)

		case strings.HasPrefix(name, ".rdata") || strings.HasPrefix(name, ".rodata"):
			sectionBase[i] = uint32(len(l.rdata))
			sectionRegion[i] = "rdata"
			l.rdata = append(l.rdata, sec.Data...)

		case strings.HasPrefix(name, ".bss"):
			sectionBase[i] = uint32(len(l.data))
			sectionRegion[i] = "data"
			l.data = append(l.data, make([]byte, sec.Header.VirtualSize)...)

		case strings.HasPrefix(name, ".data"):
			sectionBase[i] = uint32(len(l.data))
			sectionRegion[i] = "data"
			l.data = append(l.data, sec.Data...)

		case name != "" && !strings.HasPrefix(name, "."):
			// Named section (dll, mask, pico, …)
			if _, exists := l.named[name]; !exists {
				l.named[name] = nil
			}
			sectionBase[i] = uint32(len(l.named[name]))
			sectionRegion[i] = name
			l.named[name] = append(l.named[name], sec.Data...)

		default:
			sectionRegion[i] = "skip"
		}
	}

	// Pass 1b: register symbols with region-relative offsets.
	for _, sym := range obj.Symbols {
		name := sym.SymbolName(obj.Strings)
		if sym.SectionNumber <= 0 || name == "" {
			continue
		}
		secIdx := int(sym.SectionNumber) - 1
		if secIdx >= len(sectionRegion) {
			continue
		}
		region := sectionRegion[secIdx]
		if region == "skip" {
			continue
		}
		l.symbols[name] = symbolEntry{
			section: region,
			offset:  sectionBase[secIdx] + sym.Value,
		}
	}

	// Pass 1c: collect relocations (deferred).
	for i, sec := range obj.Sections {
		if sectionRegion[i] == "skip" {
			continue
		}
		region := sectionRegion[i]
		base := sectionBase[i]

		for _, rel := range sec.Relocations {
			if int(rel.SymbolTableIndex) >= len(obj.Symbols) {
				return fmt.Errorf("relocation symbol index %d out of range", rel.SymbolTableIndex)
			}
			sym := obj.Symbols[rel.SymbolTableIndex]
			symName := sym.SymbolName(obj.Strings)

			symRegion, symOff, err := l.resolveSymRef(symName, sym, sectionBase, sectionRegion)
			if err != nil {
				return fmt.Errorf("section %s reloc @%#x symbol %q: %w", sec.Name, rel.VirtualAddress, symName, err)
			}

			writeOff := base + rel.VirtualAddress

			var addend int64
			switch rel.Type {
			case coff.RelAddr32, coff.RelAddr32NB:
				addend = int64(int32(binary.LittleEndian.Uint32(l.peek(region, writeOff, 4))))
			case coff.RelAddr64:
				addend = int64(binary.LittleEndian.Uint64(l.peek(region, writeOff, 8)))
			}

			l.pending = append(l.pending, pendingReloc{
				writeRegion: region,
				writeOff:    writeOff,
				symRegion:   symRegion,
				symOff:      symOff,
				relocType:   rel.Type,
				addend:      addend,
				pcAdj:       pcAdjFor(rel.Type),
			})
		}
	}

	// +gofirst: rotation is applied in Finish() using l.symbols["go"].
	_ = modifiers
	return nil
}

func (l *Linker) resolveSymRef(
	name string, sym coff.Symbol,
	sectionBase []uint32, sectionRegion []string,
) (region string, off uint32, err error) {
	if sym.SectionNumber == coff.IMAGE_SYM_UNDEFINED {
		if e, ok := l.symbols[name]; ok {
			return e.section, e.offset, nil
		}
		return "", 0, nil // unresolved extern
	}
	if sym.SectionNumber == coff.IMAGE_SYM_ABSOLUTE {
		return "absolute", sym.Value, nil
	}
	secIdx := int(sym.SectionNumber) - 1
	if secIdx < 0 || secIdx >= len(sectionRegion) {
		return "", 0, fmt.Errorf("invalid section number %d", sym.SectionNumber)
	}
	r := sectionRegion[secIdx]
	if r == "skip" {
		return "", 0, nil
	}
	return r, sectionBase[secIdx] + sym.Value, nil
}

func (l *Linker) peek(region string, off uint32, n int) []byte {
	switch region {
	case "text":
		return l.code[off : off+uint32(n)]
	case "rdata":
		return l.rdata[off : off+uint32(n)]
	case "data":
		return l.data[off : off+uint32(n)]
	default:
		if d, ok := l.named[region]; ok {
			return d[off : off+uint32(n)]
		}
	}
	return nil
}

// SetNamedSection sets data for a named section (from spec `link "name"` directives).
func (l *Linker) SetNamedSection(name string, data []byte) {
	l.named[name] = data
}

// RegisterExport registers a named export at the given code offset.
func (l *Linker) RegisterExport(name string, offset uint32) {
	l.exports[name] = offset
}

// MergeRawCode appends a raw binary blob into the code region.
func (l *Linker) MergeRawCode(data []byte) error {
	l.code = append(l.code, data...)
	return nil
}

// NamedSection returns the data of a named section.
func (l *Linker) NamedSection(name string) ([]byte, bool) {
	d, ok := l.named[name]
	return d, ok
}

// Finish applies +gofirst rotation and all deferred relocations,
// then returns the final LinkedImage.
func (l *Linker) Finish() *LinkedImage {
	// +gofirst: rotate code so `go` is at offset 0.
	if e, ok := l.symbols["go"]; ok && e.section == "text" && e.offset > 0 {
		R := e.offset
		T := uint32(len(l.code))
		prefix := make([]byte, R)
		copy(prefix, l.code[:R])
		l.code = append(l.code[R:], prefix...)

		for name, sym := range l.symbols {
			if sym.section == "text" {
				sym.offset = (sym.offset - R + T) % T
				l.symbols[name] = sym
			}
		}
		for i := range l.pending {
			if l.pending[i].writeRegion == "text" {
				l.pending[i].writeOff = (l.pending[i].writeOff - R + T) % T
			}
			if l.pending[i].symRegion == "text" {
				l.pending[i].symOff = (l.pending[i].symOff - R + T) % T
			}
		}
	}

	cS := uint32(len(l.code))
	rS := uint32(len(l.rdata))
	dS := uint32(len(l.data))

	// Compute cumulative offsets for named sections (in the order they appear).
	// Named sections are appended AFTER [code][rdata][data] in the final blob.
	// The flat offset of named section X = cS + rS + dS + namedCumulative[X].
	namedOrder := []string{"dll", "mask", "pico"}
	namedCumBase := make(map[string]uint32)
	cum := uint32(0)
	for _, name := range namedOrder {
		if d, ok := l.named[name]; ok && len(d) > 0 {
			namedCumBase[name] = cum
			cum += uint32(len(d))
		}
	}
	// Also handle any named sections not in the canonical order.
	for name, d := range l.named {
		if _, seen := namedCumBase[name]; !seen && len(d) > 0 {
			namedCumBase[name] = cum
			cum += uint32(len(d))
		}
	}

	// Apply all deferred relocations.
	for _, rel := range l.pending {
		if rel.symRegion == "" && rel.relocType != coff.RelAbsolute {
			continue // unresolved extern — leave field as zero
		}
		if rel.symRegion == "skip" {
			continue
		}

		flatSym := l.flatOff(rel.symRegion, rel.symOff, cS, rS, dS, namedCumBase)
		flatWrite := l.flatOff(rel.writeRegion, rel.writeOff, cS, rS, dS, namedCumBase)

		loc := l.peek(rel.writeRegion, rel.writeOff, 8)
		if loc == nil {
			continue
		}

		switch rel.relocType {
		case coff.RelRel32, coff.RelRel32_1, coff.RelRel32_2,
			coff.RelRel32_3, coff.RelRel32_4, coff.RelRel32_5:
			flatPC := flatWrite + uint64(rel.pcAdj)
			binary.LittleEndian.PutUint32(loc, uint32(flatSym)-uint32(flatPC))

		case coff.RelAddr32:
			binary.LittleEndian.PutUint32(loc, uint32(flatSym)+uint32(rel.addend))

		case coff.RelAddr32NB:
			binary.LittleEndian.PutUint32(loc, uint32(flatSym)+uint32(rel.addend))

		case coff.RelAddr64:
			binary.LittleEndian.PutUint64(loc, flatSym+uint64(rel.addend))

		case coff.RelAbsolute:
			// padding no-op
		}
	}

	return &LinkedImage{
		Code:    l.code,
		RData:   l.rdata,
		Data:    l.data,
		Named:   l.named,
		Exports: l.exports,
		symbols: l.symbols,
	}
}

// flatOff converts a (region, regionOffset) pair to an absolute flat offset
// in the final [code][rdata][data][named…] blob layout.
func (l *Linker) flatOff(
	region string, off, cS, rS, dS uint32,
	namedCumBase map[string]uint32,
) uint64 {
	switch region {
	case "text":
		return uint64(off)
	case "rdata":
		return uint64(cS) + uint64(off)
	case "data":
		return uint64(cS) + uint64(rS) + uint64(off)
	case "absolute":
		return uint64(off)
	default:
		base, ok := namedCumBase[region]
		if !ok {
			return 0
		}
		return uint64(cS) + uint64(rS) + uint64(dS) + uint64(base) + uint64(off)
	}
}

func pcAdjFor(t uint16) uint32 {
	switch t {
	case coff.RelRel32:
		return 4
	case coff.RelRel32_1:
		return 5
	case coff.RelRel32_2:
		return 6
	case coff.RelRel32_3:
		return 7
	case coff.RelRel32_4:
		return 8
	case coff.RelRel32_5:
		return 9
	}
	return 4
}

// PatchNamedSections is a no-op kept for API compatibility.
func (l *Linker) PatchNamedSections() {}
