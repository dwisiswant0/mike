module go.dw1.io/mike/internal/asmgen

go 1.27.1

require github.com/mmcloughlin/avo v0.6.0

require (
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	// avo v0.6.0 requires x/tools v0.16.1, which doesn't compile with Go 1.27.
	golang.org/x/tools v0.51.0 // indirect
)
