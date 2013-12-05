package iso8583

import (
	"strconv"
)

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
	var i, flag int32
	var ch byte
	bcd := make([]byte, length/2)

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
	iso.buffer = data
	start := 0
	if iso.msgtype == ASCTYPE {
		iso.field[0].data = iso.buffer[:4]
		start += 4
	} else {
		iso.field[0].data = Bcd2Asc(iso.buffer[:2], 4, 0)
		start += 2
	}
	var bitnum int
	if iso.bittype == BCDTYPE {
		if iso.buffer[start]&0x80 != 0x80 {
			iso.field[1].data = iso.buffer[start : start+8]
			bitnum = 8
			start += 8
		} else {
			iso.field[1].data = iso.buffer[start : start+16]
			bitnum = 16
			start += 16
		}
	} else {
		if iso.buffer[start]&0x80 != 0x80 {
			iso.field[1].data = Asc2Bcd(iso.buffer[start:start+16], 16, 0)
			bitnum = 8
			start += 16
		} else {
			iso.field[1].data = Asc2Bcd(iso.buffer[start:start+32], 32, 0)
			bitnum = 16
			start += 32
		}
	}

	if bitnum == 8 {
		iso.field = make([]IsoField, 64)
	} else {
		iso.field = make([]IsoField, 128)
	}
	var i int
	var j uint

	for i = 0; i < bitnum; i++ {
		for j = 7; j >= 0; j++ {
			if (iso.field[1].data[i] & (0x01 << j)) == 0 {
				continue
			}
			bit := (i+1)*8 - int(j) - 1
			if bit == 0 {
				continue
			}

			start, _ = iso.getFiledValue(bit, start)
		}
	}
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
				length = int(iso.buffer[start]>>4)*100 + int((iso.buffer[start]&0x0f)*10) + int(iso.buffer[start+1]>>4)
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
		iso.field[bitno].data = Bcd2Asc(iso.buffer[start:start+length/2], length/2, 0)
		start += length / 2
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
	return start, nil
}
