// Command genicon draws the application icon and writes a multi-resolution
// Windows .ico file. Run it from the repository root:
//
//	go run ./tools/genicon
//
// The design matches the badge in the web interface: a rounded square with a
// blue-to-violet gradient and a white lightning bolt.
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
	"path/filepath"
)

// Sizes Windows picks between for the tray, the taskbar, Explorer and the
// alt-tab switcher.
var sizes = []int{16, 20, 24, 32, 40, 48, 64, 128, 256}

// The bolt outline, in the same 24x24 coordinate space as the SVG symbol in
// web/index.html, so the tray icon and the page badge match exactly.
var bolt = []point{
	{13, 2}, {4.5, 13.5}, {11, 13.5}, {10, 22}, {18.5, 10.5}, {12, 10.5},
}

type point struct{ X, Y float64 }

// Gradient endpoints, matching --accent and the violet it blends into.
var (
	gradFrom = color.RGBA{0x4c, 0x8d, 0xff, 0xff}
	gradTo   = color.RGBA{0x7b, 0x5c, 0xff, 0xff}
	boltFill = color.RGBA{0xff, 0xff, 0xff, 0xff}
)

const supersample = 4 // rendered at 4x then averaged down, for smooth edges

func main() {
	if err := os.MkdirAll("data", 0o755); err != nil {
		log.Fatalf("could not create data directory: %v", err)
	}

	var images []*image.RGBA
	for _, size := range sizes {
		images = append(images, render(size))
	}

	ico, err := encodeICO(images)
	if err != nil {
		log.Fatalf("could not encode icon: %v", err)
	}

	outPath := filepath.Join("data", "icon.ico")
	if err := os.WriteFile(outPath, ico, 0o644); err != nil {
		log.Fatalf("could not write %s: %v", outPath, err)
	}
	log.Printf("wrote %s: %d sizes, %.0f KB", outPath, len(images), float64(len(ico))/1024)

	// A PNG copy is handy for the web page favicon and for documentation.
	var buf bytes.Buffer
	if err := png.Encode(&buf, images[len(images)-1]); err != nil {
		log.Fatalf("could not encode PNG: %v", err)
	}
	pngPath := filepath.Join("data", "icon.png")
	if err := os.WriteFile(pngPath, buf.Bytes(), 0o644); err != nil {
		log.Fatalf("could not write %s: %v", pngPath, err)
	}
	log.Printf("wrote %s: %.0f KB", pngPath, float64(buf.Len())/1024)
}

// render draws one size of the icon.
func render(size int) *image.RGBA {
	big := size * supersample
	canvas := image.NewRGBA(image.Rect(0, 0, big, big))

	scale := float64(big) / 24.0
	radius := float64(big) * 0.22

	// Scale the bolt to sit inside the badge with a little breathing room.
	var path []point
	for _, p := range bolt {
		path = append(path, point{X: p.X * scale, Y: p.Y * scale})
	}

	for y := 0; y < big; y++ {
		for x := 0; x < big; x++ {
			fx, fy := float64(x)+0.5, float64(y)+0.5
			if !insideRoundedRect(fx, fy, float64(big), radius) {
				continue
			}
			// A diagonal blend, matching the CSS 140deg gradient.
			t := (fx + fy) / (2 * float64(big))
			canvas.Set(x, y, lerp(gradFrom, gradTo, t))
			if insidePolygon(fx, fy, path) {
				canvas.Set(x, y, boltFill)
			}
		}
	}

	return downsample(canvas, size)
}

func insideRoundedRect(x, y, side, radius float64) bool {
	if x < radius && y < radius {
		return math.Hypot(radius-x, radius-y) <= radius
	}
	if x > side-radius && y < radius {
		return math.Hypot(x-(side-radius), radius-y) <= radius
	}
	if x < radius && y > side-radius {
		return math.Hypot(radius-x, y-(side-radius)) <= radius
	}
	if x > side-radius && y > side-radius {
		return math.Hypot(x-(side-radius), y-(side-radius)) <= radius
	}
	return true
}

// insidePolygon is the standard ray-casting test.
func insidePolygon(x, y float64, poly []point) bool {
	inside := false
	for i, j := 0, len(poly)-1; i < len(poly); j, i = i, i+1 {
		if (poly[i].Y > y) != (poly[j].Y > y) &&
			x < (poly[j].X-poly[i].X)*(y-poly[i].Y)/(poly[j].Y-poly[i].Y)+poly[i].X {
			inside = !inside
		}
	}
	return inside
}

func lerp(a, b color.RGBA, t float64) color.RGBA {
	if t < 0 {
		t = 0
	}
	if t > 1 {
		t = 1
	}
	return color.RGBA{
		R: uint8(float64(a.R) + (float64(b.R)-float64(a.R))*t),
		G: uint8(float64(a.G) + (float64(b.G)-float64(a.G))*t),
		B: uint8(float64(a.B) + (float64(b.B)-float64(a.B))*t),
		A: 0xff,
	}
}

// downsample averages each block of supersample x supersample pixels, which
// is what produces the anti-aliased edges.
func downsample(src *image.RGBA, size int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a int
			for dy := 0; dy < supersample; dy++ {
				for dx := 0; dx < supersample; dx++ {
					c := src.RGBAAt(x*supersample+dx, y*supersample+dy)
					// Weight colour by coverage so transparent edges do not
					// darken towards black.
					r += int(c.R) * int(c.A) / 255
					g += int(c.G) * int(c.A) / 255
					b += int(c.B) * int(c.A) / 255
					a += int(c.A)
				}
			}
			n := supersample * supersample
			alpha := a / n
			if alpha == 0 {
				dst.SetRGBA(x, y, color.RGBA{})
				continue
			}
			// Un-premultiply back to straight alpha.
			dst.SetRGBA(x, y, color.RGBA{
				R: uint8(clamp(r * 255 / n / alpha)),
				G: uint8(clamp(g * 255 / n / alpha)),
				B: uint8(clamp(b * 255 / n / alpha)),
				A: uint8(alpha),
			})
		}
	}
	return dst
}

func clamp(v int) int {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return v
}

// encodeICO packs the images into an .ico. Every size is stored as a classic
// DIB rather than PNG: PNG entries are legal and smaller, but only newer
// consumers read them, and .NET's icon loader silently falls back to the
// largest DIB instead. A few hundred extra kilobytes is worth the certainty
// that every size loads everywhere.
func encodeICO(images []*image.RGBA) ([]byte, error) {
	var payloads [][]byte
	for _, img := range images {
		payloads = append(payloads, encodeDIB(img))
	}

	var out bytes.Buffer
	// ICONDIR: reserved, type 1 (icon), image count.
	binary.Write(&out, binary.LittleEndian, uint16(0))
	binary.Write(&out, binary.LittleEndian, uint16(1))
	binary.Write(&out, binary.LittleEndian, uint16(len(images)))

	offset := 6 + 16*len(images)
	for i, img := range images {
		size := img.Bounds().Dx()
		dim := byte(size)
		if size >= 256 {
			dim = 0 // 0 means 256 in the ICO directory
		}
		out.WriteByte(dim)                                  // width
		out.WriteByte(dim)                                  // height
		out.WriteByte(0)                                    // palette size
		out.WriteByte(0)                                    // reserved
		binary.Write(&out, binary.LittleEndian, uint16(1))  // colour planes
		binary.Write(&out, binary.LittleEndian, uint16(32)) // bits per pixel
		binary.Write(&out, binary.LittleEndian, uint32(len(payloads[i])))
		binary.Write(&out, binary.LittleEndian, uint32(offset))
		offset += len(payloads[i])
	}
	for _, payload := range payloads {
		out.Write(payload)
	}
	return out.Bytes(), nil
}

// encodeDIB writes a bottom-up 32-bit BGRA bitmap plus the 1-bit AND mask that
// the ICO format still requires, even for images that carry their own alpha.
func encodeDIB(img *image.RGBA) []byte {
	w := img.Bounds().Dx()
	h := img.Bounds().Dy()

	maskRowBytes := ((w + 31) / 32) * 4
	maskSize := maskRowBytes * h

	var buf bytes.Buffer
	// BITMAPINFOHEADER. The height is doubled to cover image plus mask.
	binary.Write(&buf, binary.LittleEndian, uint32(40))
	binary.Write(&buf, binary.LittleEndian, int32(w))
	binary.Write(&buf, binary.LittleEndian, int32(h*2))
	binary.Write(&buf, binary.LittleEndian, uint16(1))
	binary.Write(&buf, binary.LittleEndian, uint16(32))
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // BI_RGB
	binary.Write(&buf, binary.LittleEndian, uint32(w*h*4+maskSize))
	binary.Write(&buf, binary.LittleEndian, int32(0))
	binary.Write(&buf, binary.LittleEndian, int32(0))
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	binary.Write(&buf, binary.LittleEndian, uint32(0))

	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			c := img.RGBAAt(x, y)
			buf.WriteByte(c.B)
			buf.WriteByte(c.G)
			buf.WriteByte(c.R)
			buf.WriteByte(c.A)
		}
	}

	// Fully zeroed mask: the alpha channel above does the work.
	buf.Write(make([]byte, maskSize))
	return buf.Bytes()
}
