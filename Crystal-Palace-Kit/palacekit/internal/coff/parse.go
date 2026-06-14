package coff

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

func Parse(data []byte) (*Object, error) {
	r := bytes.NewReader(data)
	obj := &Object{}

	if err := binary.Read(r, binary.LittleEndian, &obj.Header); err != nil {
		return nil, fmt.Errorf("read file header: %w", err)
	}
	if obj.Header.Machine != MachineAMD64 {
		return nil, fmt.Errorf("unsupported machine type 0x%04x (expected AMD64)", obj.Header.Machine)
	}

	headers := make([]SectionHeader, obj.Header.NumberOfSections)
	for i := range headers {
		if err := binary.Read(r, binary.LittleEndian, &headers[i]); err != nil {
			return nil, fmt.Errorf("read section header %d: %w", i, err)
		}
	}

	// Read string table (needed for long section names)
	var strTable []byte
	if obj.Header.PointerToSymbolTable > 0 && obj.Header.NumberOfSymbols > 0 {
		strOffset := int(obj.Header.PointerToSymbolTable) + int(obj.Header.NumberOfSymbols)*18
		if strOffset < len(data) {
			var strSize uint32
			binary.Read(bytes.NewReader(data[strOffset:]), binary.LittleEndian, &strSize)
			if strOffset+int(strSize) <= len(data) {
				strTable = data[strOffset : strOffset+int(strSize)]
			}
		}
	}
	obj.Strings = strTable

	// Parse sections
	obj.Sections = make([]Section, len(headers))
	for i, h := range headers {
		sec := Section{Header: h}
		sec.Name = sectionName(h.Name, strTable)

		if h.SizeOfRawData > 0 && h.PointerToRawData > 0 {
			end := int(h.PointerToRawData) + int(h.SizeOfRawData)
			if end > len(data) {
				return nil, fmt.Errorf("section %d data out of bounds", i)
			}
			sec.Data = make([]byte, h.SizeOfRawData)
			copy(sec.Data, data[h.PointerToRawData:end])
		}

		if h.NumberOfRelocations > 0 && h.PointerToRelocations > 0 {
			relOff := int(h.PointerToRelocations)
			sec.Relocations = make([]Relocation, h.NumberOfRelocations)
			relReader := bytes.NewReader(data[relOff:])
			for j := range sec.Relocations {
				if err := binary.Read(relReader, binary.LittleEndian, &sec.Relocations[j]); err != nil {
					return nil, fmt.Errorf("read relocation %d in section %d: %w", j, i, err)
				}
			}
		}

		obj.Sections[i] = sec
	}

	// Parse symbol table
	if obj.Header.PointerToSymbolTable > 0 && obj.Header.NumberOfSymbols > 0 {
		symOff := int(obj.Header.PointerToSymbolTable)
		symReader := bytes.NewReader(data[symOff:])
		obj.Symbols = make([]Symbol, obj.Header.NumberOfSymbols)
		for i := range obj.Symbols {
			if err := binary.Read(symReader, binary.LittleEndian, &obj.Symbols[i]); err != nil {
				if err == io.EOF {
					obj.Symbols = obj.Symbols[:i]
					break
				}
				return nil, fmt.Errorf("read symbol %d: %w", i, err)
			}
		}
	}

	return obj, nil
}

func sectionName(raw [8]byte, strTable []byte) string {
	if raw[0] == '/' && len(strTable) > 0 {
		// Long name: "/offset" into string table
		numStr := strings.TrimRight(string(raw[1:]), "\x00")
		var offset int
		fmt.Sscanf(numStr, "%d", &offset)
		if offset < len(strTable) {
			end := bytes.IndexByte(strTable[offset:], 0)
			if end < 0 {
				return string(strTable[offset:])
			}
			return string(strTable[offset : offset+end])
		}
	}
	end := bytes.IndexByte(raw[:], 0)
	if end < 0 {
		end = 8
	}
	return string(raw[:end])
}

func (sym *Symbol) SymbolName(strTable []byte) string {
	if sym.Name[0] == 0 && sym.Name[1] == 0 && sym.Name[2] == 0 && sym.Name[3] == 0 {
		offset := binary.LittleEndian.Uint32(sym.Name[4:])
		if int(offset) < len(strTable) {
			end := bytes.IndexByte(strTable[offset:], 0)
			if end < 0 {
				return string(strTable[offset:])
			}
			return string(strTable[int(offset) : int(offset)+end])
		}
		return ""
	}
	end := bytes.IndexByte(sym.Name[:], 0)
	if end < 0 {
		end = 8
	}
	return string(sym.Name[:end])
}
