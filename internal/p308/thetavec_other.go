// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

//go:build !goexperiment.simd || !amd64

package p308

// thetaChain runs steps 2-isogeny steps from domain, with the stack of theta
// points in points, and returns the last codomain. This build has no vector
// code path; see thetavec_amd64.go.
func thetaChain(domain theta4Structure, points []theta4, levels []int, top, steps int) theta4Structure {
	return scalarThetaChain(domain, points, levels, top, steps)
}
