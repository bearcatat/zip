package zip

import "unicode/utf8"

func Isutf8(s string) bool {
	return utf8.ValidString(s)
}

func Isgbk(s string) bool {
	if Isutf8(s) {
		return false
	}
	data := []byte(s)
	length := len(data)
	var i int = 0
	for i < length {
		if data[i] <= 0xff {
			i++
			continue
		} else {
			if data[i] >= 0x81 &&
				data[i] <= 0xfe &&
				data[i+1] >= 0x40 &&
				data[i+1] <= 0xfe &&
				data[i+1] != 0xf7 {
				i += 2
				continue
			} else {
				return false
			}
		}
	}
	return true
}
