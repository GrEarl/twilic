package core

import (
	"bytes"
	"math"
	"testing"
)

func TestSecurityDecodeDepth(t *testing.T) {
	data := append(bytes.Repeat([]byte{0xa1}, 70), 0xc0)
	if _, err := Decode(data); err == nil {
		t.Fatal("missing depth rejection")
	}
	if _, err := Decode([]byte{0xa0}); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityOversizedStrRefDoesNotPanic(t *testing.T) {
	// str_ref (0xd9) with a large varuint id must reject without panicking.
	data := []byte{0xd9, 0xf8, 0x8c, 0xa6, 0xe1, 0xa1, 0x92, 0x8f, 0x84, 0x84, 0x01}
	if _, err := Decode(data); err == nil {
		t.Fatal("missing str_ref rejection")
	}
}

func TestSecurityI64ForOverflowDoesNotWrap(t *testing.T) {
	// Typed-vector FOR reconstruction must reject overflowing additions.
	shifted := []int64{math.MaxInt64}
	var payload []byte
	encodeVaruint(encodeZigzag(1), &payload)
	encodeI64DirectBitpack(shifted, &payload)
	reader := newReader(payload)
	if _, err := decodeI64Vector(reader, VectorCodecForBitpack); err == nil {
		t.Fatal("missing i64 FOR overflow rejection")
	}
}

func TestSecurityI64PatchedForOverflowDoesNotWrap(t *testing.T) {
	// Patched FOR reconstruction must reject overflowing base additions.
	var payload []byte
	encodeVaruint(1, &payload)                      // length
	encodeVaruint(encodeZigzag(math.MaxInt64), &payload) // base
	payload = append(payload, 0)                    // base width
	encodeVaruint(1, &payload)                      // main value
	encodeVaruint(0, &payload)                      // patch count
	reader := newReader(payload)
	if _, err := decodeI64Vector(reader, VectorCodecPatchedFor); err == nil {
		t.Fatal("missing i64 patched FOR overflow rejection")
	}
}

func TestSecurityReaderBudgets(t *testing.T) {
	r := newReader([]byte{0})
	if err := r.claimOutput(100); err != nil {
		t.Fatal(err)
	}
	if err := r.claimOutput(100); err == nil {
		t.Fatal("missing cumulative budget")
	}
	if _, err := newReader([]byte{0}).readExact(-1); err == nil {
		t.Fatal("negative length accepted")
	}
	var data []byte
	for _, n := range []uint64{1, 0, 100000} {
		encodeVaruint(n, &data)
	}
	if _, err := decodeU64Rle(newReader(data)); err == nil {
		t.Fatal("RLE expansion accepted")
	}
}
