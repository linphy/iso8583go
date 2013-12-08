package iso8583

import (
	"errors"
	"fmt"
	"strconv"
)

const DEBUG = true
const MAX_ISO_DATA = (1024 * 1)
const MIN_ISO_LEN = 10
const FIELD_MAX_SIZE = 512

const ISO_LEN_MASK = 0x03 /*The Mask Is:When LenType=(Iso->type >> 6)*/
const ISO_LEN_FIX = 0x00
const ISO_LEN_VAR2 = 0x01
const ISO_LEN_VAR3 = 0x02

/* 以下长度类型只能选一个 */
const ISOLV3 = 0x80
const ISOLV2 = 0x40
const ISOLFIX = 0x00

/* 以下数据类型只能选一个 */
const ISO_DATA_MASK = 0x3C /*The Mask Is:When DatType=(Iso->type & 0x3F)*/
const ISODEBC = 0x20
const ISODBIN = 0x10
const ISODBCD = 0x08
const ISODC_D = 0x04
const ISODASC = 0x00

/* 以下填充类型只能选一个 */
const ISO_FIL_MASK = 0x02 /*The Mask Is:When DatType=(Iso->type & 0x3F)*/
const ISOFSP = 0x02
const ISOF0 = 0x00

/* 以下对齐类型只能选一个 */
const ISO_JUST_MASK = 0x01 /*The Mask Is:When DatType=(Iso->type & 0x3F)*/
const ISORJUST = 0x01
const ISOLJUST = 0x00

/*TYPE*/
const BCDTYPE = 0
const ASCTYPE = 1
const HEXTYPE = 2

type IsoExDef struct {
	length int16
	def    byte
}

type IsoField struct {
	bitflag, length int16
	data            []byte
}

type IsoEx struct {
	buffer  []byte
	msgtype int16
	bittype int16
	lentype int16
	field   []IsoField
	iso_def []IsoExDef
}

var IsoExDefYL = []IsoExDef{
	{64, ISOLFIX | ISODBCD | ISOF0 | ISOLJUST},
	{19, ISOLV2 | ISODBCD | ISOF0 | ISOLJUST},
	{6, ISOLFIX | ISODBCD | ISOF0 | ISOLJUST},
	{12, ISOLFIX | ISODBCD | ISOF0 | ISORJUST},
	{12, ISOLFIX | ISODASC | ISOF0 | ISORJUST}, /*  Field[  5]  */
	{12, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{10, ISOLFIX | ISODBCD | ISOF0 | ISORJUST},
	{8, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{8, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{8, ISOLFIX | ISODASC | ISOF0 | ISORJUST}, /*  Field[ 10]  */
	{6, ISOLFIX | ISODBCD | ISOF0 | ISORJUST},
	{6, ISOLFIX | ISODBCD | ISOF0 | ISORJUST},
	{4, ISOLFIX | ISODBCD | ISOF0 | ISORJUST},
	{4, ISOLFIX | ISODBCD | ISOF0 | ISORJUST},
	{4, ISOLFIX | ISODBCD | ISOF0 | ISORJUST}, /*  Field[ 15]  */
	{4, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{4, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{4, ISOLFIX | ISODBCD | ISOF0 | ISORJUST},
	{3, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{3, ISOLFIX | ISODASC | ISOF0 | ISORJUST}, /*  Field[ 20]  */
	{3, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{3, ISOLFIX | ISODBCD | ISOF0 | ISOLJUST},
	{3, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{3, ISOLFIX | ISODBCD | ISOF0 | ISORJUST},
	{2, ISOLFIX | ISODBCD | ISOF0 | ISORJUST}, /*  Field[ 25]  */
	{2, ISOLFIX | ISODBCD | ISOF0 | ISORJUST},
	{1, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{8, ISOLFIX | ISODC_D | ISOF0 | ISORJUST},
	{8, ISOLFIX | ISODC_D | ISOF0 | ISORJUST},
	{8, ISOLFIX | ISODC_D | ISOF0 | ISORJUST}, /*  Field[ 30]  */
	{8, ISOLFIX | ISODC_D | ISOF0 | ISORJUST},
	{11, ISOLV2 | ISODBCD | ISOF0 | ISOLJUST},
	{11, ISOLV2 | ISODASC | ISOF0 | ISOLJUST},
	{28, ISOLV2 | ISODASC | ISOFSP | ISOLJUST},
	{37, ISOLV2 | ISODBCD | ISOF0 | ISOLJUST}, /*  Field[ 35]  */
	{104, ISOLV3 | ISODBCD | ISOF0 | ISOLJUST},
	{12, ISOLFIX | ISODASC | ISOFSP | ISOLJUST},
	{6, ISOLFIX | ISODASC | ISOFSP | ISOLJUST},
	{2, ISOLFIX | ISODASC | ISOFSP | ISOLJUST},
	{3, ISOLFIX | ISODASC | ISOFSP | ISOLJUST}, /*  Field[ 40]  */
	{8, ISOLFIX | ISODASC | ISOFSP | ISOLJUST},
	{15, ISOLFIX | ISODASC | ISOFSP | ISOLJUST},
	{40, ISOLFIX | ISODASC | ISOF0 | ISOLJUST},
	{25, ISOLV2 | ISODASC | ISOFSP | ISOLJUST},
	{76, ISOLV2 | ISODBCD | ISOF0 | ISOLJUST}, /*  Field[ 45]  */
	{8, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{62, ISOLV3 | ISODBCD | ISOF0 | ISOLJUST},
	{3, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{3, ISOLFIX | ISODASC | ISOF0 | ISORJUST}, /*  Field[ 50]  */
	{3, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{64, ISOLFIX | ISODBIN | ISOF0 | ISOLJUST},
	{16, ISOLFIX | ISODBCD | ISOF0 | ISORJUST},
	{20, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST}, /*  Field[ 55]  */
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{17, ISOLV3 | ISODBCD | ISOF0 | ISOLJUST}, /*  Field[ 60]  */
	{29, ISOLV3 | ISODBCD | ISOF0 | ISOLJUST},
	{24, ISOLV3 | ISODASC | ISOF0 | ISOLJUST},
	{63, ISOLV3 | ISODASC | ISOF0 | ISOLJUST},
	{64, ISOLFIX | ISODBIN | ISOF0 | ISOLJUST},
	{64, ISOLFIX | ISODBIN | ISOF0 | ISOLJUST}, /*  Field[ 65]  */
	{1, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{2, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{3, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{3, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{3, ISOLFIX | ISODASC | ISOF0 | ISORJUST}, /*  Field[ 70]  */
	{4, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{4, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{6, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{10, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{10, ISOLFIX | ISODASC | ISOF0 | ISORJUST}, /*  Field[ 75]  */
	{10, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{10, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{10, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{10, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{10, ISOLFIX | ISODASC | ISOF0 | ISORJUST}, /*  Field[ 80]  */
	{10, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{12, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{12, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{12, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{12, ISOLFIX | ISODASC | ISOF0 | ISORJUST}, /*  Field[ 85]  */
	{16, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{16, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{16, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{16, ISOLFIX | ISODASC | ISOF0 | ISORJUST},
	{42, ISOLFIX | ISODASC | ISOF0 | ISOLJUST}, /*  Field[ 90]  */
	{1, ISOLFIX | ISODASC | ISOFSP | ISOLJUST},
	{2, ISOLFIX | ISODASC | ISOFSP | ISOLJUST},
	{5, ISOLFIX | ISODASC | ISOFSP | ISOLJUST},
	{7, ISOLFIX | ISODASC | ISOFSP | ISOLJUST},
	{42, ISOLFIX | ISODASC | ISOFSP | ISOLJUST}, /*  Field[ 95]  */
	{64, ISOLFIX | ISODBIN | ISOF0 | ISOLJUST},
	{16, ISOLFIX | ISODC_D | ISOF0 | ISORJUST},
	{25, ISOLFIX | ISODASC | ISOFSP | ISOLJUST},
	{11, ISOLV2 | ISODASC | ISOF0 | ISOLJUST},
	{11, ISOLV2 | ISODASC | ISOF0 | ISOLJUST}, /*  Field[100]  */
	{17, ISOLV2 | ISODASC | ISOFSP | ISOLJUST},
	{28, ISOLV2 | ISODASC | ISOFSP | ISOLJUST},
	{28, ISOLV2 | ISODASC | ISOFSP | ISOLJUST},
	{100, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST}, /*  Field[105]  */
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST}, /*  Field[110]  */
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST}, /*  Field[115]  */
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST}, /*  Field[120]  */
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST}, /*  Field[125]  */
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{999, ISOLV3 | ISODASC | ISOFSP | ISOLJUST},
	{64, ISOLFIX | ISODBIN | ISOF0 | ISOLJUST}}

func Asc2Bcd(asc []byte, length int32, r_align int32) []byte {
	var i, flag, bcd_len int32
	var ch byte
	if length%2 == 1 {
		bcd_len = (length + 1) / 2
	} else {
		bcd_len = length / 2
	}
	bcd := make([]byte, bcd_len)

	if (length%2) == 1 && r_align == 1 {
		flag = 1
	}

	for i = 0; i < length; i++ {
		if asc[i] >= 'a' {
			ch = asc[i] - 'a' + 10
		} else if asc[i] >= 'A' {
			ch = asc[i] - 'A' + 10
		} else if asc[i] >= '0' {
			ch = asc[i] - '0'
		} else {
			ch = 0
		}
		if (i+flag)%2 == 1 {
			bcd[(i+flag)/2] |= (ch & 0x0F)
		} else {
			bcd[(i+flag)/2] |= (ch << 4)
		}
	}

	return bcd
}

func Bcd2Asc(bcd []byte, length int, r_align int) []byte {
	var i, flag int
	asc := make([]byte, length)

	if (length%2) == 1 && r_align == 1 {
		flag = 1
	}

	for i = 0; i < length; i++ {
		if (i+flag)%2 == 1 {
			asc[i] = bcd[(i+flag)/2] & 0x0F
		} else {
			asc[i] = (bcd[(i+flag)/2] >> 4)
		}
		if asc[i] > 9 {
			asc[i] += ('A' - 10)
		} else {
			asc[i] += '0'
		}
	}

	return asc
}

func NewIsoEx(msgtype, bittype, lentype int16, isodef []IsoExDef) (*IsoEx, error) {
	iso := new(IsoEx)
	iso.msgtype = msgtype
	iso.bittype = bittype
	iso.lentype = lentype
	iso.iso_def = isodef

	return iso, nil
}

func (iso *IsoEx) Str2IsoEx(data []byte) error {
	if len(data) == 0 {
		return errors.New("data len err")
	}
	DumpHex(data)
	iso.buffer = data
	buf_len := len(iso.buffer)
	//DumpHex(iso.buffer[:2])
	start := 0
	var msgid []byte
	if iso.msgtype == ASCTYPE {
		msgid = iso.buffer[:4]
		start += 4
	} else {
		msgid = Bcd2Asc(iso.buffer[:2], 4, 0)
		start += 2
	}

	var bitnum int
	var bitbuffer []byte
	if iso.bittype == BCDTYPE {
		if iso.buffer[start]&0x80 != 0x80 {
			bitbuffer = iso.buffer[start : start+8]
			bitnum = 8
			start += 8
		} else {
			bitbuffer = iso.buffer[start : start+16]
			bitnum = 16
			start += 16
		}
	} else {
		if iso.buffer[start]&0x80 != 0x80 {
			bitbuffer = Asc2Bcd(iso.buffer[start:start+16], 16, 0)
			bitnum = 8
			start += 16
		} else {
			bitbuffer = Asc2Bcd(iso.buffer[start:start+32], 32, 0)
			bitnum = 16
			start += 32
		}
	}

	if bitnum == 8 {
		iso.field = make([]IsoField, 64)
	} else {
		iso.field = make([]IsoField, 128)
	}
	iso.field[0].data = msgid
	iso.field[1].data = bitbuffer

	DumpHex(iso.field[0].data)
	DumpHex(iso.field[1].data)
	fmt.Printf("start=[%d]\n", start)
	var i int
	var j int

	for i = 0; i < bitnum; i++ {
		for j = 7; j >= 0; j-- {
			j_bak := uint(j)
			if (bitbuffer[i] & (0x01 << j_bak)) == 0 {
				//fmt.Printf("[%02x]j=%d\n", bitbuffer[i], j)
				//fmt.Printf("0")
				continue
			}
			bit := (i+1)*8 - j - 1
			if bit == 0 {
				//fmt.Printf("1")
				continue
			}
			//fmt.Printf("1")
			//fmt.Printf("[%d][%d]1", i, j)
			if start > buf_len {
				return fmt.Errorf("iso.data Invalid Memory Access,now point to %d,and bit number is %d", start, bit)
			}
			start, _ = iso.getFiledValue(bit, start)
		}
	}
	fmt.Printf("\n")
	return nil
}

func (iso *IsoEx) getFiledValue(bitno int, start int) (int, error) {
	len_type := int(iso.iso_def[bitno].def >> 6)
	dat_type := int(iso.iso_def[bitno].def & 0x3F)

	var length int
	if len_type == 0 {
		length = int(iso.iso_def[bitno].length)
	} else {
		if iso.lentype == BCDTYPE {
			if len_type == 1 {
				length = int(iso.buffer[start]>>4)*10 + int(iso.buffer[start]&0x0f)
				start += 1 //LENGTH LL2
			} else {
				length = int(iso.buffer[start]&0x0f)*100 + int((iso.buffer[start+1]>>4)*10) + int(iso.buffer[start+1]&0x0f)
				start += 2 //LENGTH LL3
			}
		} else {
			if len_type == 1 {
				length, _ = strconv.Atoi(string(iso.buffer[start : start+2]))
				start += 2 //LENGTH LL2
			} else {
				length, _ = strconv.Atoi(string(iso.buffer[start : start+3]))
				start += 3 //LENGTH LL3
			}
		}
	}

	switch dat_type & ISO_DATA_MASK {
	case ISODBCD:
		var char_len int
		if length%2 == 0 {
			char_len = length / 2
			iso.field[bitno].data = Bcd2Asc(iso.buffer[start:start+char_len], char_len*2, 0)
		} else {
			char_len = (length + 1) / 2
			if iso.iso_def[bitno].def&ISO_JUST_MASK == 0x01 {
				iso.field[bitno].data = Bcd2Asc(iso.buffer[start:start+char_len], length, 1)
			} else {
				iso.field[bitno].data = Bcd2Asc(iso.buffer[start:start+char_len], length, 0)
			}
		}
		start += char_len
	case ISODASC:
		iso.field[bitno].data = iso.buffer[start : start+length]
		start += length
	case ISODBIN:
		iso.field[bitno].data = iso.buffer[start : start+length/8]
		start += length / 8
	case ISODC_D:
		iso.field[bitno].data = iso.buffer[start : start+length+1] /*借记,贷记数据,定义时没有包括'C'或 'D'*/
		start += length + 1
	default:
		iso.field[bitno].data = iso.buffer[start : start+length]
		start += length
	}

	iso.field[bitno].bitflag = 1
	if len(iso.field[bitno].data) > int(iso.iso_def[bitno].length) {
		return start, errors.New("filed data exceed def max length")
	}
	Debug("%03d--%03d--%03d--[%s]\n", bitno+1, length, start, iso.field[bitno].data)

	return start, nil
}

func (iso *IsoEx) Iso2StrEx() ([]byte, error) {
	bitnum := 8 //默认8字节位图
	if len(iso.field) > 64 {
		bitnum = 16
	}
	var msg_data []byte
	if iso.msgtype == BCDTYPE {
		msg_data = Asc2Bcd(iso.field[0].data, 4, 0)
	} else {
		msg_data = iso.field[0].data[:4]
	}
	var i int
	var j int
	var bitbuffer, tmp_data, data []byte

	bitbuffer = make([]byte, bitnum)
	tmp_data = make([]byte, 0, 1024)

	for i = 0; i < bitnum; i++ {
		for j = 7; j >= 0; j-- {
			bit := (i+1)*8 - j - 1
			if bit == 0 {
				continue
			}
			if iso.field[bit].bitflag == 0 {
				continue
			}
			j_bak := uint(j)
			bitbuffer[i] |= (0x01 << j_bak)
			ret_data, err := iso.setFiledValue(bit, iso.field[bit].data)
			if err != nil {
				return nil, errors.New("setFiledValue failed ")
			}
			tmp_data = append(tmp_data, ret_data...)
		}
	}
	if bitnum == 16 {
		bitbuffer[0] |= 0x80
	}
	// if iso.msgtype == ASCTYPE {
	// 	tmp_bitbuffer = Bcd2Asc(bitbuffer, len(bitbuffer)*2, 0)
	// }
	data = append(data, msg_data...)
	data = append(data, bitbuffer...)
	data = append(data, tmp_data...)
	return data, nil
}

func (iso *IsoEx) setFiledValue(bitno int, data []byte) ([]byte, error) {
	if iso.field[bitno].bitflag == 0 {
		return nil, nil
	}
	len_type := int(iso.iso_def[bitno].def >> 6)
	dat_type := int(iso.iso_def[bitno].def & 0x3F)

	var tmp_data []byte
	char_len := len(data)
	switch dat_type & ISO_DATA_MASK {
	case ISODBCD:
		if iso.iso_def[bitno].def&ISO_JUST_MASK == 0x01 {
			tmp_data = Asc2Bcd(data, int32(char_len), 1)
		} else {
			tmp_data = Asc2Bcd(data, int32(char_len), 0)
		}
	default:
		tmp_data = data
	}

	length := len(iso.field[bitno].data)
	var filed_data []byte
	switch len_type {
	case ISO_LEN_FIX:
		filed_data = tmp_data
	case ISO_LEN_VAR2:
		if iso.lentype == BCDTYPE {
			filed_data = make([]byte, 1)
			filed_data[0] = (byte(char_len/10) << 4) | byte(char_len%10)
		} else {
			filed_data = make([]byte, 2)
			filed_data = []byte(fmt.Sprintf("%02d", length))
		}
		filed_data = append(filed_data, tmp_data...)
	case ISO_LEN_VAR3:
		if iso.lentype == BCDTYPE {
			filed_data = make([]byte, 2)
			filed_data[0] = byte(length / 100)
			filed_data[1] = (byte(length/10) << 4) | byte(length%10)
		} else {
			filed_data = make([]byte, 3)
			filed_data = []byte(fmt.Sprintf("%03d", length))
		}
		filed_data = append(filed_data, tmp_data...)
	}
	DumpHex(filed_data)
	return filed_data, nil

}
func DumpHex(data []byte) error {
	if !DEBUG {
		return nil
	}
	for i := 0; i < len(data); i++ {
		if (i+1)%25 != 0 {
			fmt.Printf("%02x ", data[i])
		} else {
			fmt.Printf("%02x\n", data[i])
		}
	}
	fmt.Printf("\n")
	return nil
}

func Debug(format string, a ...interface{}) error {
	if !DEBUG {
		return nil
	}
	fmt.Printf(format, a...)
	return nil
}
