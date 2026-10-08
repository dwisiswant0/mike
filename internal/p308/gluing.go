// Copyright 2026 Dwi Siswanto ("dwisiswant0"). All rights reserved.
// Use of this source code is governed by the Apache License, Version 2.0,
// that can be found in the LICENSE file.

package p308

// This file implements the first three steps of the dimension-4 isogeny,
// which move from elliptic curve points to theta points:
//
//  1. The Scholten isogeny E × E^σ → A × A, where E^σ is the Frobenius
//     conjugate of E and A is an abelian surface. Coordinates drop from
//     GF(p²) to GF(p) here.
//  2. A diagonal isogeny A × A → A' × A', computed as two isogenies in
//     dimension 2.
//  3. The gluing isogeny A' × A' → B into an abelian fourfold B.
//
// A point of E^4 is represented by two points of E, because the other two
// coordinates are their Frobenius conjugates.

// kernelPoints holds the kernel data of the three gluing steps, as points on
// E.
type kernelPoints struct {
	scholten [2]point    // P8, Q8: order 8
	diagonal [2]point    // Q16, P16: order 16
	gluing   [3][2]point // order 32
}

// pointPair is a point of E^4, given by two points of E.
type pointPair [2]point

// scholten holds the precomputed values for evaluating the Scholten
// isogeny.
type scholten struct {
	e             *curve
	shift         point  // P8, used to evaluate points as P ± P8
	a, b, c, d, f fp     // constants from the change of basis
	j             theta2 // codomain data
}

// newScholten precomputes the Scholten isogeny with kernel determined by
// kerP and kerQ, where [4]kerQ = (0, 0).
func newScholten(ell *curve, kerP, kerQ *point) *scholten {
	basis := scholtenBasis(ell, kerP)

	// J = (y : y : x : x) from the images of the kernel points.
	imgP := squaredTheta(&basis, kerP)
	imgQ := squaredTheta(&basis, kerQ)

	imgP.hadamard()
	imgQ.hadamard()

	var (
		res            scholten
		thetaX, thetaY fp
	)

	thetaX.mul(&imgP.x, &imgQ.z)
	thetaY.mul(&imgP.z, &imgQ.x)

	res.e = ell
	res.shift = *kerP
	res.j = theta2{x: thetaY, y: thetaY, z: thetaX, t: thetaX}

	var sq0, sq1, sq2 fp

	sq0.square(&basis[0])
	sq1.square(&basis[1])
	sq2.square(&basis[2])
	res.a.add(&sq1, &sq2)
	res.b.sub(&sq0, &sq1)
	res.c.sub(&sq0, &sq2)
	res.d.mul(&basis[0], &basis[1]).mul4(&res.d)
	res.f.mul(&basis[2], &basis[3]).mul4(&res.f)

	return &res
}

// scholtenBasis returns the coefficients (m0, m1, m2, m3) of the change of
// basis that makes the action of Frobenius symmetric. They come from
// x([2]kerP) = (α : β).
func scholtenBasis(ell *curve, kerP *point) [4]fp {
	halfP := kerP.toX()
	ell.xdbl(&halfP)
	alpha, beta := &halfP.x, &halfP.z
	normA, normB := alpha.norm(), beta.norm()

	var coeffs [4]fp

	coeffs[0].add(&normA, &normB)
	coeffs[2].sub(&normB, &normA)

	var cross fp2

	cross.conjugate(beta).mul(&cross, alpha).double(&cross)
	coeffs[1] = cross.re
	coeffs[3] = cross.im

	return coeffs
}

// squaredTheta maps P on E to the theta point of (P, σ(P)) after the
// symmetric change of basis, and returns its coordinate-wise square.
//
// For x(P) = (X : Z), the theta point is (n(X) : X·conj(Z) : conj(X)·Z :
// n(Z)), where n is the norm. After the change of basis, three coordinates
// lie in GF(p) and the fourth is i times an element of GF(p), so the squares
// all lie in GF(p).
func squaredTheta(basis *[4]fp, src *point) theta2 {
	srcX := src.toX()
	normX, normZ := srcX.x.norm(), srcX.z.norm()

	var cross fp2

	cross.conjugate(&srcX.z).mul(&cross, &srcX.x).double(&cross)

	var sum, diff fp

	sum.add(&normX, &normZ)
	diff.sub(&normX, &normZ)

	crossRe, crossIm := &cross.re, &cross.im

	var (
		res theta2
		tmp fp
	)

	res.x.mul(&basis[0], &sum).sub(&res.x, tmp.mul(&basis[1], crossRe))
	res.y.mul(&basis[0], crossRe).sub(&res.y, tmp.mul(&basis[1], &sum))
	res.z.mul(&basis[2], &diff).sub(&res.z, tmp.mul(&basis[3], crossIm))
	res.t.mul(&basis[2], crossIm).add(&res.t, tmp.mul(&basis[3], &diff))
	res.x.square(&res.x)
	res.y.square(&res.y)
	res.z.square(&res.z)
	res.t.square(&res.t)
	res.t.neg(&res.t) // the square of i·T

	return res
}

// image returns the image of (P, −σ(P)) under the Scholten isogeny. If
// changeBasis is set, the result is also moved to the basis used by the
// following isogenies.
func (s *scholten) image(src *point, changeBasis bool) theta2 {
	compU, compV, compW := s.e.addComponents(src, &s.shift)
	normU, normV, normW := compU.norm(), compV.norm(), compW.norm()

	// tPlus = u² − v² + w² and tMinus = u² − v² − w².
	var sqU, sqV, sqW, acc, tPlus, tMinus fp2

	sqU.square(&compU)
	sqV.square(&compV)
	sqW.square(&compW)
	acc.sub(&sqU, &sqV)
	tPlus.add(&acc, &sqW)
	tMinus.sub(&acc, &sqW)
	normPlus, normMinus := tPlus.norm(), tMinus.norm()

	// U + i·V = tPlus·conj(u·w).
	acc.mul(&compU, &compW).conjugate(&acc).mul(&acc, &tPlus)
	bigU, bigV := &acc.re, &acc.im

	var normUW, termDU, termFV, tmp fp

	normUW.mul(&normU, &normW).mul4(&normUW)
	termDU.mul(&s.d, bigU)
	termFV.mul(&s.f, bigV)

	var res theta2
	// α = a·n(tPlus) + 4c·n(u)·n(w) − d·U − f·V
	res.x.mul(&s.a, &normPlus).add(&res.x, tmp.mul(&s.c, &normUW)).sub(&res.x, &termDU).sub(&res.x, &termFV)
	// β = b·n(tMinus)
	res.y.mul(&s.b, &normMinus)
	// γ = c·n(tPlus) + 4a·n(u)·n(w) − d·U + f·V
	res.z.mul(&s.c, &normPlus).add(&res.z, tmp.mul(&s.a, &normUW)).sub(&res.z, &termDU).add(&res.z, &termFV)
	// δ = −4b·n(v)·n(w), the sign being fixed because MIKE evaluates
	// (P, −σ(P)).
	res.t.mul(&normV, &normW).mul4(&res.t).mul(&res.t, tmp.neg(&s.b))

	res.mulCoords(&s.j)
	res.hadamard()

	if changeBasis {
		res.scholtenBasisChange()
	}

	return res
}

// uFromV derives the kernel point U from V, as H ∘ (negate t) ∘ H.
func uFromV(ptV *theta2) theta2 {
	var sumXT, diffXT, sumYZ, diffYZ fp

	sumXT.add(&ptV.x, &ptV.t)
	diffXT.sub(&ptV.x, &ptV.t)
	sumYZ.add(&ptV.y, &ptV.z)
	diffYZ.sub(&ptV.y, &ptV.z)

	var res theta2

	res.x.add(&diffXT, &sumYZ)
	res.y.add(&sumXT, &diffYZ)
	res.z.sub(&sumXT, &diffYZ)
	res.t.sub(&sumYZ, &diffXT)

	return res
}

// gluingIsogeny computes the three gluing steps for the kernel data. It
// returns the codomain, a theta structure in dimension 4, and the images of
// points.
func gluingIsogeny(ell *curve, data *kernelPoints, points []pointPair) (theta4Structure, []theta4) {
	// Step 1: the Scholten isogeny E × E^σ → A × A.
	diag, imgU, imgV := scholtenStep(ell, data, points)

	// Step 2: the diagonal isogeny A × A → A' × A', evaluated as two
	// isogenies of abelian surfaces. The U half is evaluated as a dual
	// isogeny: its inputs move to dual coordinates, while the V half moves
	// its outputs.
	const dual, direct = true, false

	nullU := twoIsogeny2(&diag[0], &diag[1], imgU, dual, direct)
	nullV := twoIsogeny2(&diag[2], &diag[3], imgV, direct, dual)

	// Extend the gluing kernel with the image of the sum of the second and
	// third kernel points.
	kernel := [4][2]theta2{
		{imgU[0], imgV[0]},
		{imgU[1], imgV[1]},
		{imgU[2], imgV[2]},
		{diffAdd(&nullU, &imgU[2], &imgU[1], &imgU[0]), diffAdd(&nullV, &imgV[2], &imgV[1], &imgV[0])},
	}

	// Step 3: the gluing isogeny A' × A' → B into an abelian fourfold.
	gluingLen := len(data.gluing)

	return fourfoldGluing(&kernel, imgU[gluingLen:], imgV[gluingLen:])
}

// scholtenStep evaluates the Scholten isogeny on the kernel data and on
// points. It returns the diagonal kernel (U1, U2, V1, V2), and the images as
// two lists, imgU and imgV, holding the first and second halves of each
// point of A × A: three gluing kernel points, then the images of P + T for
// each P in points, then those of P − T. Here T is the first gluing kernel
// point; the final gluing step combines the images of P ± T into the image
// of P.
func scholtenStep(ell *curve, data *kernelPoints, points []pointPair) ([4]theta2, []theta2, []theta2) {
	isog := newScholten(ell, &data.scholten[0], &data.scholten[1])

	// The points Ui follow from Vi, before the change of basis.
	imgV1 := isog.image(&data.diagonal[0], false)
	imgV2 := isog.image(&data.diagonal[1], false)

	diag := [4]theta2{uFromV(&imgV2), uFromV(&imgV1), imgV1, imgV2}
	for idx := range diag {
		diag[idx].scholtenBasisChange()
	}

	size := len(data.gluing) + len(points) + len(points)
	imgU := make([]theta2, 0, size)
	imgV := make([]theta2, 0, size)

	for _, pair := range data.gluing {
		imgU = append(imgU, isog.image(&pair[0], true))
		imgV = append(imgV, isog.image(&pair[1], true))
	}

	shift := &data.gluing[0]
	for _, pair := range points {
		sumU := ell.add(&pair[0], &shift[0])
		sumV := ell.add(&pair[1], &shift[1])

		imgU = append(imgU, isog.image(&sumU, true))
		imgV = append(imgV, isog.image(&sumV, true))
	}

	for _, pair := range points {
		diffU := ell.sub(&pair[0], &shift[0])
		diffV := ell.sub(&pair[1], &shift[1])

		imgU = append(imgU, isog.image(&diffU, true))
		imgV = append(imgV, isog.image(&diffV, true))
	}

	return diag, imgU, imgV
}

// fourfoldGluing computes the final gluing isogeny A' × A' → B with the
// given kernel. The lists imgU and imgV hold the halves of the images of
// P + T for each point P to evaluate, followed by those of P − T, as
// returned by scholtenStep. It returns the codomain and the images of the
// points P.
func fourfoldGluing(kernelData *[4][2]theta2, imgU, imgV []theta2) (theta4Structure, []theta4) {
	var kernel [4]theta4
	for idx := range kernel {
		kernel[idx] = product(&kernelData[idx][0], &kernelData[idx][1])
		kernel[idx].square()
		kernel[idx].hadamard()
	}

	invDual, invT3 := gluingCodomain(&kernel)
	codomain := newTheta4Structure(gluingNull(&invDual))

	// The image of P is H(invT3 ⋆ H((P + T) ⋆ (P − T))).
	count := len(imgU) >> 1

	images := make([]theta4, count)
	for idx := range images {
		plus := product(&imgU[idx], &imgV[idx])
		minus := product(&imgU[count+idx], &imgV[count+idx])
		plus.mulCoords(&minus)
		plus.hadamard()
		plus.mulCoords(&invT3)
		plus.hadamard()
		images[idx] = plus
	}

	return codomain, images
}

// gluingNull returns the null point of the gluing codomain, the Hadamard
// transform of the inverse of invDual. Six coordinates of invDual are zero;
// gluingNull inverts the other ten.
func gluingNull(invDual *theta4) *theta4 {
	nonZero := [...]int{0, 1, 2, 3, 4, 6, 8, 9, 12, 15}

	var coords [len(nonZero)]fp
	for idx, coord := range nonZero {
		coords[idx] = invDual[coord]
	}

	projectiveInvert(coords[:])

	var null theta4
	for idx, coord := range nonZero {
		null[coord] = coords[idx]
	}

	null.hadamard()

	return &null
}

// product returns the dimension-4 theta point of (lhs, rhs) ∈ A × A, after
// the change of basis used by the gluing isogeny.
func product(lhs, rhs *theta2) theta4 {
	lhsCoords := [...]*fp{&lhs.x, &lhs.y, &lhs.z, &lhs.t}
	rhsCoords := [...]*fp{&rhs.x, &rhs.y, &rhs.z, &rhs.t}

	var res theta4

	for i, lhsCoord := range lhsCoords {
		for j, rhsCoord := range rhsCoords {
			res[i+len(lhsCoords)*j].mul(lhsCoord, rhsCoord)
		}
	}

	res.gluingBasisChange()

	return res
}

// gluingCodomain returns the inverse of the dual null point of the gluing
// codomain and the inverse of the translation point T3, both up to scaling,
// from the squared and transformed kernel points.
func gluingCodomain(kernel *[4]theta4) (theta4, theta4) {
	// Three "legs" of products from the first three kernel points.
	var leg4, leg8, leg12 [3]fp

	leg4[0].mul(&kernel[0][4], &kernel[0][6])
	leg4[1].mul(&kernel[0][0], &kernel[0][6])
	leg4[2].mul(&kernel[0][0], &kernel[0][2])
	leg8[0].mul(&kernel[1][8], &kernel[1][9])
	leg8[1].mul(&kernel[1][0], &kernel[1][9])
	leg8[2].mul(&kernel[1][0], &kernel[1][1])
	leg12[0].mul(&kernel[2][12], &kernel[2][15])
	leg12[1].mul(&kernel[2][0], &kernel[2][15])
	leg12[2].mul(&kernel[2][0], &kernel[2][3])

	// The compressed inverse null point; entries 4, 6, and 8 are zero.
	var (
		compressed theta4c
		tmp        fp
	)

	tmp.mul(&leg8[0], &leg12[0])
	compressed[0].mul(&tmp, &leg4[0])
	compressed[2].mul(&tmp, &leg4[1])
	compressed[5].mul(&tmp, &leg4[2])
	tmp.mul(&leg4[0], &leg12[0])
	compressed[1].mul(&tmp, &leg8[1])
	compressed[7].mul(&tmp, &leg8[2])
	tmp.mul(&leg4[0], &leg8[0])
	compressed[3].mul(&tmp, &leg12[1])
	compressed[9].mul(&tmp, &leg12[2])
	invNull := compressed.expand()

	return invNull, inverseT3(kernel, &invNull)
}

// inverseT3 returns the inverse of the translation point T3, up to scaling.
func inverseT3(kernel *[4]theta4, invNull *theta4) theta4 {
	// The eight distinct coordinates of T3 are kernel[0] ⋆ invNull at
	// indices 0, 1, 2, 3, 8, 9, 10, 15. Coordinate 10 vanishes there, so it
	// is recovered from the fourth kernel point instead, scaling the others
	// by the denominator kernel[3][8]·invNull[8] to avoid an inversion.
	indices := [...]int{0, 1, 2, 3, 8, 9, 10, 15}

	var coordsT3 [len(indices)]fp
	for idx, coord := range indices {
		coordsT3[idx].mul(&kernel[0][coord], &invNull[coord])
	}

	var coord10, den fp

	coord10.mul(&coordsT3[0], &kernel[3][2]).mul(&coord10, &invNull[2])
	den.mul(&kernel[3][8], &invNull[8])

	for idx := range coordsT3 {
		coordsT3[idx].mul(&coordsT3[idx], &den)
	}

	coordsT3[6] = coord10

	projectiveInvert(coordsT3[:])

	// invT3[8i + j] = invT3[8i + j + 4] = coordsT3[4i + j].
	var invT3 theta4

	for i := range 2 {
		for j := range 4 {
			invT3[8*i+j] = coordsT3[4*i+j]
			invT3[8*i+j+4] = coordsT3[4*i+j]
		}
	}

	return invT3
}
