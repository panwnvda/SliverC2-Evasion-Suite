// Flat-binary COFF linker for MaskKit.
// Produces [code][rdata][data] — no named sections, no spec DSL.
//
// Two-pass design:
//   Pass 1 (MergeObject): append section bytes, register symbols.
//   Pass 2 (Assemble): apply +gofirst rotation, then apply all deferred
//     relocations now that final section sizes are known.
//
// This avoids the classic single-pass pitfall where cross-region REL32
// displacements (text→data, text→rdata) are computed before the final
// section sizes are known, giving wrong values.
package link

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"maskkit/internal/coff"
)

type symbolEntry struct {
	section string // "text", "rdata", "data"
	offset  uint32 // region-relative (0-based from start of region)
}

// pendingReloc stores a relocation to be applied after all sections are merged.
type pendingReloc struct {
	writeRegion string // "text", "rdata", "data"
	writeOff    uint32 // region-relative byte offset of the field to patch
	symRegion   string // "" = unresolved extern (stays 0)
	symOff      uint32 // region-relative byte offset of target symbol
	relocType   uint16
	addend      int64  // existing value at write site (for ADDR variants)
	pcAdj       uint32 // bytes from field start to next instruction (4 for REL32, 5 for REL32_1…)
}

type Linker struct {
	code    []byte
	rdata   []byte
	data    []byte
	symbols map[string]symbolEntry
	pending []pendingReloc
}

func New() *Linker {
	return &Linker{symbols: make(map[string]symbolEntry)}
}

// MergeObject appends a COFF object's sections and defers its relocations.
// goFirst is noted but rotation is deferred to Assemble() so all region sizes
// are known before we adjust any offsets.
func (l *Linker) MergeObject(obj *coff.Object, goFirst bool) error {
	sectionBase := make([]uint32, len(obj.Sections))
	sectionRegion := make([]string, len(obj.Sections))

	// Pass 1a: append section data, record region-relative base offsets.
	for i, sec := range obj.Sections {
		ch := sec.Header.Characteristics
		switch {
		case strings.HasPrefix(sec.Name, ".text") || ch&coff.IMAGE_SCN_CNT_CODE != 0:
			sectionBase[i] = uint32(len(l.code))
			sectionRegion[i] = "text"
			l.code = append(l.code, sec.Data...)
		case strings.HasPrefix(sec.Name, ".rdata") || strings.HasPrefix(sec.Name, ".rodata"):
			sectionBase[i] = uint32(len(l.rdata))
			sectionRegion[i] = "rdata"
			l.rdata = append(l.rdata, sec.Data...)
		case strings.HasPrefix(sec.Name, ".bss"):
			sectionBase[i] = uint32(len(l.data))
			sectionRegion[i] = "data"
			l.data = append(l.data, make([]byte, sec.Header.VirtualSize)...)
		case strings.HasPrefix(sec.Name, ".data"):
			sectionBase[i] = uint32(len(l.data))
			sectionRegion[i] = "data"
			l.data = append(l.data, sec.Data...)
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
		if secIdx >= len(sectionRegion) || sectionRegion[secIdx] == "skip" {
			continue
		}
		l.symbols[name] = symbolEntry{
			section: sectionRegion[secIdx],
			offset:  sectionBase[secIdx] + sym.Value,
		}
	}

	// Pass 1c: collect relocations (deferred — do not patch yet).
	for i, sec := range obj.Sections {
		if sectionRegion[i] == "skip" {
			continue
		}
		region := sectionRegion[i]
		base := sectionBase[i]

		for _, rel := range sec.Relocations {
			if int(rel.SymbolTableIndex) >= len(obj.Symbols) {
				return fmt.Errorf("reloc sym idx %d OOB in section %s", rel.SymbolTableIndex, sec.Name)
			}
			sym := obj.Symbols[rel.SymbolTableIndex]
			symName := sym.SymbolName(obj.Strings)

			symRegion, symOff, err := l.resolveSymRef(symName, sym, sectionBase, sectionRegion)
			if err != nil {
				return fmt.Errorf("sec %s reloc @%#x sym %q: %w", sec.Name, rel.VirtualAddress, symName, err)
			}

			writeOff := base + rel.VirtualAddress

			// Read existing addend from the raw section bytes (for ADDR variants).
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

	_ = goFirst // rotation handled in Assemble() via "go" symbol lookup
	return nil
}

// resolveSymRef returns the (region, regionOffset) of a relocation target.
// For undefined externals that remain unresolved, returns ("", 0, nil) — the
// reloc will leave the field as zero (IAT stubs that the C code doesn't call).
func (l *Linker) resolveSymRef(
	name string, sym coff.Symbol,
	sectionBase []uint32, sectionRegion []string,
) (region string, off uint32, err error) {
	if sym.SectionNumber == coff.IMAGE_SYM_UNDEFINED {
		if e, ok := l.symbols[name]; ok {
			return e.section, e.offset, nil
		}
		return "", 0, nil // unresolved → leave as zero
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

// peek reads n bytes from a region at the given region-relative offset.
func (l *Linker) peek(region string, off uint32, n int) []byte {
	switch region {
	case "text":
		return l.code[off : off+uint32(n)]
	case "rdata":
		return l.rdata[off : off+uint32(n)]
	case "data":
		return l.data[off : off+uint32(n)]
	}
	return nil
}

// Assemble applies +gofirst rotation and all deferred relocations,
// then returns the flat PIC shellcode: [code][rdata][data].
func (l *Linker) Assemble() []byte {
	// +gofirst: rotate l.code so that `go` lands at offset 0.
	if e, ok := l.symbols["go"]; ok && e.section == "text" && e.offset > 0 {
		R := e.offset
		T := uint32(len(l.code))

		prefix := make([]byte, R)
		copy(prefix, l.code[:R])
		l.code = append(l.code[R:], prefix...)

		// Shift every text-region symbol and every pending reloc's text offset.
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

	// Apply all deferred relocations now that final sizes are known.
	for _, rel := range l.pending {
		if rel.symRegion == "" && rel.relocType != coff.RelAbsolute {
			continue // unresolved extern — leave field as zero
		}
		if rel.symRegion == "skip" {
			continue
		}

		flatSym := flatOffset(rel.symRegion, rel.symOff, cS, rS)
		flatWrite := flatOffset(rel.writeRegion, rel.writeOff, cS, rS)

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

	var buf bytes.Buffer
	buf.Write(l.code)
	buf.Write(l.rdata)
	buf.Write(l.data)
	return buf.Bytes()
}

// flatOffset converts a region-relative offset to a flat [code][rdata][data] offset.
func flatOffset(region string, off, codeSize, rdataSize uint32) uint64 {
	switch region {
	case "text":
		return uint64(off)
	case "rdata":
		return uint64(codeSize) + uint64(off)
	case "data":
		return uint64(codeSize) + uint64(rdataSize) + uint64(off)
	case "absolute":
		return uint64(off)
	}
	return 0
}

// pcAdjFor returns the byte count from a REL32 field's start to the next instruction.
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

// SymbolOffset returns a symbol's byte offset in the assembled blob, or -1.
func (l *Linker) SymbolOffset(name string) int {
	if e, ok := l.symbols[name]; ok {
		cS := len(l.code)
		rS := len(l.rdata)
		switch e.section {
		case "text":
			return int(e.offset)
		case "rdata":
			return cS + int(e.offset)
		case "data":
			return cS + rS + int(e.offset)
		}
	}
	return -1
}
