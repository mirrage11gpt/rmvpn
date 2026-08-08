package webembed

import "embed"

// Dist is replaced by the Vite production build.
//
//go:embed all:dist
var Dist embed.FS
