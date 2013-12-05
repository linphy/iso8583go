package iso8583

import (
	//"fmt"
	"testing"
)

func TestNewIsoEx(t *testing.T) {
	iso, err := NewIsoEx(0, 0, 0, IsoExDefYL)
	if err != nil {
		t.Fatal("new IsoEx err")
	}
	if iso.bittype != 0 {
		t.Fatal("new IsoEx err")
	}
	//fmt.Println(iso)
}

func TestStr2IsoEx(t *testing.T) {
	iso, err := NewIsoEx(0, 0, 0, IsoExDefYL)
	if err != nil {
		t.Fatal("new IsoEx err")
	}

	data := []byte{0x02, 0x20, 0x70, 0x24, 0x04, 0x80, 0x2c, 0xc0, 0x88, 0x18, 0x19, 0x88,
		0x80, 0x19, 0x10, 0x00, 0x00, 0x04, 0x90, 0x49, 0x60, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x00, 0x10, 0x82, 0x88, 0x80, 0x02, 0x10,
		0x00, 0x33, 0x88, 0x80, 0x19, 0x10, 0x00, 0x00, 0x04, 0x90, 0x49, 0x6d, 0x00, 0x00, 0x00, 0x10, 0x64, 0x12, 0x20, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30,
		0x33, 0x37, 0x32, 0x37, 0x34, 0x37, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x38, 0x38, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x38, 0x31, 0x39, 0x35, 0x34,
		0x31, 0x31, 0x30, 0x30, 0x30, 0x31, 0x30, 0x30, 0x30, 0x31, 0x31, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x25, 0x00,
		0x00, 0x05, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	iso.Str2IsoEx(data)
	//fmt.Println(iso)
}

/*
Field[  0] Len[  4] Data:[0220]
Field[  2] Len[ 19] Data:[8880191000000490496]
Field[  3] Len[  6] Data:[200000]
Field[  4] Len[ 12] Data:[000000000056]
Field[ 11] Len[  6] Data:[001082]
Field[ 14] Len[  4] Data:[8880]
Field[ 22] Len[  3] Data:[021]
Field[ 25] Len[  2] Data:[00]
Field[ 35] Len[ 33] Data:[8880191000000490496**************]
Field[ 37] Len[ 12] Data:[010100372747]
Field[ 38] Len[  6] Data:[      ]
Field[ 41] Len[  8] Data:[88654321]
Field[ 42] Len[ 15] Data:[819541100010001]
Field[ 49] Len[  3] Data:[156]
Field[ 53] Len[ 16] Data:[0000000000000000]
Field[ 60] Len[  8] Data:[25000005]
Field[ 61] Len[ 12] Data:[000000000000]
*/
