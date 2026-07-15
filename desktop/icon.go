package main

// icon.go draws the menu-bar icon at runtime (a small node mesh) so there's no
// binary asset to ship. It's a black template image with alpha; macOS tints it
// automatically for light/dark menu bars.

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

func iconPNG() []byte {
	const s = 44
	img := image.NewNRGBA(image.Rect(0, 0, s, s))
	black := color.NRGBA{R: 0, G: 0, B: 0, A: 255}

	// Five nodes with one interior hub (index 2), echoing the project logo.
	nodes := [5][2]int{{11, 13}, {33, 10}, {22, 22}, {12, 34}, {34, 33}}

	// Edges from the hub, then a couple of perimeter links.
	for i := 0; i < 5; i++ {
		if i != 2 {
			drawLine(img, nodes[2], nodes[i], black)
		}
	}
	drawLine(img, nodes[0], nodes[1], black)
	drawLine(img, nodes[3], nodes[4], black)

	for i, n := range nodes {
		r := 3
		if i == 2 {
			r = 4
		}
		fillDisc(img, n[0], n[1], r, black)
	}

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func fillDisc(img *image.NRGBA, cx, cy, r int, c color.NRGBA) {
	b := img.Bounds()
	for y := cy - r; y <= cy+r; y++ {
		for x := cx - r; x <= cx+r; x++ {
			dx, dy := x-cx, y-cy
			if dx*dx+dy*dy <= r*r && image.Pt(x, y).In(b) {
				img.SetNRGBA(x, y, c)
			}
		}
	}
}

func drawLine(img *image.NRGBA, a, b [2]int, c color.NRGBA) {
	x0, y0 := float64(a[0]), float64(a[1])
	x1, y1 := float64(b[0]), float64(b[1])
	steps := int(math.Hypot(x1-x0, y1-y0)) + 1
	for i := 0; i <= steps; i++ {
		t := float64(i) / float64(steps)
		x := int(math.Round(x0 + (x1-x0)*t))
		y := int(math.Round(y0 + (y1-y0)*t))
		fillDisc(img, x, y, 1, c)
	}
}
