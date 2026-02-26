package auth

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func TestNormalizeToWebPRejectsOversizedDimensions(t *testing.T) {
	raw := pngHeaderOnly(5000, 5000)

	_, err := normalizeToWebP(raw, 256)
	if !errors.Is(err, errImageTooLargeDimensions) {
		t.Fatalf("expected oversized-dimensions error, got: %v", err)
	}
}

func TestNormalizeToWebPSucceedsForSmallPNG(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 32, 24))
	for y := 0; y < 24; y++ {
		for x := 0; x < 32; x++ {
			img.SetRGBA(x, y, color.RGBA{R: uint8(x * 7), G: uint8(y * 9), B: 120, A: 255})
		}
	}

	var src bytes.Buffer
	if err := png.Encode(&src, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}

	out, err := normalizeToWebP(src.Bytes(), 256)
	if err != nil {
		t.Fatalf("normalizeToWebP failed: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected non-empty webp output")
	}
}

func pngHeaderOnly(width, height uint32) []byte {
	const pngSig = "\x89PNG\r\n\x1a\n"

	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], width)
	binary.BigEndian.PutUint32(ihdr[4:8], height)
	ihdr[8] = 8  // bit depth
	ihdr[9] = 2  // color type: truecolor
	ihdr[10] = 0 // compression
	ihdr[11] = 0 // filter
	ihdr[12] = 0 // interlace

	var out bytes.Buffer
	out.WriteString(pngSig)
	writePNGChunk(&out, "IHDR", ihdr)
	writePNGChunk(&out, "IEND", nil)
	return out.Bytes()
}

func writePNGChunk(out *bytes.Buffer, chunkType string, data []byte) {
	_ = binary.Write(out, binary.BigEndian, uint32(len(data)))
	out.WriteString(chunkType)
	out.Write(data)

	sum := crc32.NewIEEE()
	sum.Write([]byte(chunkType))
	sum.Write(data)
	_ = binary.Write(out, binary.BigEndian, sum.Sum32())
}
