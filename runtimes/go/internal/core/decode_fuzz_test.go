package core

import (
	"bytes"
	"testing"
)

func FuzzDecode(f *testing.F) {
	for _, seed := range [][]byte{
		{0},
		{0, 0},
		{2},
		{0x90},
		append(bytes.Repeat([]byte{0xA1}, 8), 0xC0),
		{0xD3, 0xFF, 0xFF, 0xFF, 0xFF},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Decode(data)
		codec := NewTwilicCodec()
		_, _ = codec.DecodeMessage(data)
		_, _ = codec.DecodeValue(data)
	})
}
