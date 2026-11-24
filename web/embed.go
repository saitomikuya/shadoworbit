package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embeddedDist embed.FS

// DistFS is the embedded Vite build filesystem rooted at dist/.
var DistFS fs.FS

func init() {
	sub, err := fs.Sub(embeddedDist, "dist")
	if err != nil {
		panic(err)
	}
	DistFS = sub
}
