package coff

const MachineAMD64 = uint16(0x8664)

const (
	RelAbsolute = uint16(0x0000)
	RelAddr64   = uint16(0x0001)
	RelAddr32   = uint16(0x0002)
	RelAddr32NB = uint16(0x0003)
	RelRel32    = uint16(0x0004)
	RelRel32_1  = uint16(0x0005)
	RelRel32_2  = uint16(0x0006)
	RelRel32_3  = uint16(0x0007)
	RelRel32_4  = uint16(0x0008)
	RelRel32_5  = uint16(0x0009)
	RelSection  = uint16(0x000A)
	RelSecRel   = uint16(0x000B)
)

const (
	IMAGE_SYM_CLASS_EXTERNAL    = uint8(2)
	IMAGE_SYM_CLASS_STATIC      = uint8(3)
	IMAGE_SYM_CLASS_LABEL       = uint8(6)
	IMAGE_SYM_CLASS_SECTION     = uint8(104)
	IMAGE_SYM_UNDEFINED         = int16(0)
	IMAGE_SYM_ABSOLUTE          = int16(-1)
	IMAGE_SYM_DEBUG             = int16(-2)
)

const (
	IMAGE_SCN_CNT_CODE               = uint32(0x00000020)
	IMAGE_SCN_CNT_INITIALIZED_DATA   = uint32(0x00000040)
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = uint32(0x00000080)
	IMAGE_SCN_MEM_EXECUTE            = uint32(0x20000000)
	IMAGE_SCN_MEM_READ               = uint32(0x40000000)
	IMAGE_SCN_MEM_WRITE              = uint32(0x80000000)
)

type FileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type SectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type Relocation struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

type Symbol struct {
	Name               [8]byte
	Value              uint32
	SectionNumber      int16
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}

type Section struct {
	Header      SectionHeader
	Data        []byte
	Relocations []Relocation
	Name        string
}

type Object struct {
	Header   FileHeader
	Sections []Section
	Symbols  []Symbol
	Strings  []byte
}
